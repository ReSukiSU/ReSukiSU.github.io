use android_bootimg::{
    cpio::{Cpio, CpioEntry},
    parser::BootImage,
    patcher::BootImagePatchOption,
};
use anyhow::{anyhow, Context, Result};
use std::{cell::RefCell, io::Cursor};

#[link(wasm_import_module = "env")]
extern "C" {
    fn report_progress(message_ptr: *const u8, message_len: usize, percent: u32);
}

fn report(message: &str, percent: u32) {
    unsafe { report_progress(message.as_ptr(), message.len(), percent) };
}

thread_local! {
    static RESULT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static ERROR: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut input = Vec::<u8>::with_capacity(size);
    let ptr = input.as_mut_ptr();
    std::mem::forget(input);
    ptr
}

#[no_mangle]
pub unsafe extern "C" fn patch_vr(input_ptr: *mut u8, input_len: usize) -> u32 {
    let input = Vec::from_raw_parts(input_ptr, input_len, input_len);
    match patch_vendor_boot(&input) {
        Ok(output) => {
            RESULT.with(|slot| *slot.borrow_mut() = output);
            ERROR.with(|slot| slot.borrow_mut().clear());
            1
        }
        Err(error) => {
            RESULT.with(|slot| slot.borrow_mut().clear());
            ERROR.with(|slot| *slot.borrow_mut() = format!("{error:#}").into_bytes());
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn result_ptr() -> *const u8 {
    RESULT.with(|slot| slot.borrow().as_ptr())
}

#[no_mangle]
pub extern "C" fn result_len() -> usize {
    RESULT.with(|slot| slot.borrow().len())
}

#[no_mangle]
pub extern "C" fn error_ptr() -> *const u8 {
    ERROR.with(|slot| slot.borrow().as_ptr())
}

#[no_mangle]
pub extern "C" fn error_len() -> usize {
    ERROR.with(|slot| slot.borrow().len())
}

fn patch_vendor_boot(image_data: &[u8]) -> Result<Vec<u8>> {
    report("parse_image", 5);
    let boot_image = BootImage::parse(image_data).context("parse_boot_image")?;
    let ramdisk = boot_image
        .get_blocks()
        .get_ramdisk()
        .ok_or_else(|| anyhow!("missing_ramdisk"))?;

    if !ramdisk.is_vendor_ramdisk() {
        return Err(anyhow!("not_vendor_boot_v4"));
    }

    report("find_ramdisk", 15);
    let (index, target) = ramdisk
        .iter_vendor_ramdisk()
        .enumerate()
        .find(|(_, entry)| entry.get_name_raw() == b"init_boot")
        .or_else(|| {
            ramdisk
                .iter_vendor_ramdisk()
                .enumerate()
                .find(|(_, entry)| entry.get_name_raw().is_empty())
        })
        .ok_or_else(|| anyhow!("missing_vendor_ramdisk_entry"))?;

    report("decompress_ramdisk", 25);
    let mut unpacked = Vec::new();
    target
        .dump(&mut unpacked, false)
        .context("decompress_vendor_ramdisk")?;
    report("parse_cpio", 40);
    let mut cpio = Cpio::load_from_data(&unpacked).context("parse_vendor_ramdisk_cpio")?;

    report("remove_module", 55);
    remove_vr_module(&mut cpio)?;

    report("rebuild_cpio", 75);
    let mut rebuilt_cpio = Vec::new();
    cpio.dump(&mut rebuilt_cpio).context("rebuild_cpio")?;

    let mut patcher = BootImagePatchOption::new(&boot_image);
    patcher.replace_vendor_ramdisk(index, Box::new(Cursor::new(rebuilt_cpio)), false);

    report("repack_image", 88);
    let mut output = Cursor::new(Vec::new());
    patcher.patch(&mut output).context("repack_vendor_boot")?;
    report("complete", 100);
    Ok(output.into_inner())
}

fn remove_vr_module(cpio: &mut Cpio) -> Result<()> {
    let mut roots = vec!["lib/modules".to_string()];
    for path in cpio.entries().keys() {
        let Some(rest) = path.strip_prefix("lib/modules/") else {
            continue;
        };
        let head = rest.split('/').next().unwrap_or_default();
        if !head.is_empty() && head.ends_with("-gki") {
            let candidate = format!("lib/modules/{head}");
            if !roots.contains(&candidate) {
                roots.push(candidate);
            }
        }
    }

    for root in roots {
        let module_path = format!("{root}/vr.ko");
        if cpio.exists(&module_path) {
            report(&format!("removed:{module_path}"), 60);
            cpio.rm(&module_path, false);
        } else {
            report(&format!("not_found:{root}"), 60);
        }
        for name in [
            "modules.load",
            "modules.dep",
            "modules.softdep",
            "modules.load.recovery",
        ] {
            remove_from_index(cpio, &format!("{root}/{name}"))?;
        }
    }
    Ok(())
}

fn remove_from_index(cpio: &mut Cpio, path: &str) -> Result<()> {
    let Some(entry) = cpio.entry_by_name(path) else {
        return Ok(());
    };
    let Some(data) = entry.data() else {
        return Err(anyhow!("invalid_index_file:{path}"));
    };

    let text = String::from_utf8_lossy(data);
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| {
            let value = line.trim();
            !(value.contains("vr.ko")
                || value.contains("/vr.ko")
                || value.contains(" vr ")
                || value.ends_with(" vr")
                || value.starts_with("vr ")
                || value.starts_with("softdep vr "))
        })
        .collect();

    if kept.len() == text.lines().count() {
        return Ok(());
    }
    report(&format!("cleaned:{path}"), 68);
    let mut rebuilt = kept.join("\n");
    if !rebuilt.is_empty() {
        rebuilt.push('\n');
    }
    cpio.rm(path, false);
    cpio.add(
        path,
        CpioEntry::regular(0o644, Box::new(rebuilt.into_bytes())),
    )?;
    Ok(())
}
