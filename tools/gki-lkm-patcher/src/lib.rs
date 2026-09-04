use android_bootimg::{
    cpio::{Cpio, CpioEntry},
    parser::BootImage,
    patcher::BootImagePatchOption,
};
use anyhow::{anyhow, Context, Result};
use regex_lite::Regex;
use std::{cell::RefCell, io::Cursor};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

thread_local! {
    static PROGRESS_CALLBACK: RefCell<Option<js_sys::Function>> = const { RefCell::new(None) };
}

#[wasm_bindgen]
pub fn set_progress_callback(callback: js_sys::Function) {
    PROGRESS_CALLBACK.with(|slot| *slot.borrow_mut() = Some(callback));
}

fn report(value: &str, percent: u32) {
    PROGRESS_CALLBACK.with(|slot| {
        if let Some(callback) = slot.borrow().as_ref() {
            let _ = callback.call2(
                &JsValue::NULL,
                &JsValue::from_str(value),
                &JsValue::from_f64(percent.into()),
            );
        }
    });
}
thread_local! { static RESULT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) }; static ERROR: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) }; }

#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(size);
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}
#[no_mangle]
pub extern "C" fn result_ptr() -> *const u8 {
    RESULT.with(|v| v.borrow().as_ptr())
}
#[no_mangle]
pub extern "C" fn result_len() -> usize {
    RESULT.with(|v| v.borrow().len())
}
#[no_mangle]
pub extern "C" fn error_ptr() -> *const u8 {
    ERROR.with(|v| v.borrow().as_ptr())
}
#[no_mangle]
pub extern "C" fn error_len() -> usize {
    ERROR.with(|v| v.borrow().len())
}
fn finish(result: Result<Vec<u8>>) -> u32 {
    match result {
        Ok(v) => {
            RESULT.with(|s| *s.borrow_mut() = v);
            ERROR.with(|s| s.borrow_mut().clear());
            1
        }
        Err(e) => {
            ERROR.with(|s| *s.borrow_mut() = format!("{e:#}").into_bytes());
            0
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn detect_kmi(ptr: *mut u8, len: usize) -> u32 {
    let input = Vec::from_raw_parts(ptr, len, len);
    finish((|| {
        let image = BootImage::parse(&input).context("parse_boot_image")?;
        let kernel = image
            .get_blocks()
            .get_kernel()
            .ok_or_else(|| anyhow!("missing_kernel_for_kmi"))?;
        let mut data = Vec::new();
        kernel.dump(&mut data, false)?;
        Ok(parse_kmi(&data)?.into_bytes())
    })())
}

#[no_mangle]
pub unsafe extern "C" fn patch_lkm(
    ip: *mut u8,
    il: usize,
    mp: *mut u8,
    ml: usize,
    kp: *mut u8,
    kl: usize,
) -> u32 {
    let image = Vec::from_raw_parts(ip, il, il);
    let module = Vec::from_raw_parts(mp, ml, ml);
    let init = Vec::from_raw_parts(kp, kl, kl);
    finish(patch(&image, module, init))
}

fn parse_kmi(data: &[u8]) -> Result<String> {
    let re = Regex::new(r"(\d+\.\d+)(?:\S+)?(android\d+)")?;
    for (i, b) in data.windows(3).enumerate() {
        if b[1] != b'.' || !matches!(b[0], b'5' | b'6') || !b[2].is_ascii_digit() {
            continue;
        }
        let s = &data[i..data.len().min(i + 100)];
        let end = s.iter().position(|v| *v == 0).unwrap_or(s.len());
        if let Ok(s) = std::str::from_utf8(&s[..end]) {
            if let Some(c) = re.captures(s) {
                return Ok(format!("{}-{}", &c[2], &c[1]));
            }
        }
    }
    Err(anyhow!("kmi_not_found"))
}

fn patch(data: &[u8], module: Vec<u8>, init: Vec<u8>) -> Result<Vec<u8>> {
    report("parse_image", 40);
    let image = BootImage::parse(data).context("parse_boot_image")?;
    let mut patcher = BootImagePatchOption::new(&image);
    let (mut cpio, vendor) = if let Some(r) = image.get_blocks().get_ramdisk() {
        if r.is_vendor_ramdisk() {
            let (i, e) = r
                .iter_vendor_ramdisk()
                .enumerate()
                .find(|(_, e)| e.get_name_raw().is_empty())
                .or_else(|| {
                    r.iter_vendor_ramdisk()
                        .enumerate()
                        .find(|(_, e)| e.get_name_raw() == b"init_boot")
                })
                .ok_or_else(|| anyhow!("missing_vendor_ramdisk_entry"))?;
            let mut d = Vec::new();
            e.dump(&mut d, false)?;
            (Cpio::load_from_data(&d)?, Some(i))
        } else {
            let mut d = Vec::new();
            r.dump(&mut d, false)?;
            (Cpio::load_from_data(&d)?, None)
        }
    } else {
        (Cpio::new(), None)
    };
    if cpio.is_magisk_patched() {
        return Err(anyhow!("magisk_patched"));
    }
    report("inject_lkm", 65);
    if !cpio.exists("kernelsu.ko") && cpio.exists("init") {
        cpio.mv("init", "init.real")?;
    }
    cpio.add("init", CpioEntry::regular(0o755, Box::new(init)))?;
    cpio.add("kernelsu.ko", CpioEntry::regular(0o755, Box::new(module)))?;
    let mut rebuilt = Vec::new();
    cpio.dump(&mut rebuilt)?;
    if let Some(i) = vendor {
        patcher.replace_vendor_ramdisk(i, Box::new(Cursor::new(rebuilt)), false);
    } else {
        patcher.replace_ramdisk(Box::new(Cursor::new(rebuilt)), false);
    }
    report("repack_image", 85);
    let mut out = Cursor::new(Vec::new());
    patcher.patch(&mut out)?;
    report("complete", 100);
    Ok(out.into_inner())
}
