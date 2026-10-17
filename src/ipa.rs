//! IPA unpacking and repacking, plus the Info.plist edits made before signing.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;

/// An IPA unpacked into a temporary directory, removed on drop.
pub struct Unpacked {
    work: PathBuf,
    pub app: PathBuf,
}

impl Drop for Unpacked {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.work);
    }
}

pub fn unpack(ipa: &Path) -> Result<Unpacked> {
    let work = std::env::temp_dir().join(format!("appman-{}", std::process::id()));
    if work.exists() {
        std::fs::remove_dir_all(&work)?;
    }
    std::fs::create_dir_all(&work)?;
    let file = File::open(ipa).with_context(|| format!("opening {}", ipa.display()))?;
    zip::ZipArchive::new(file)?.extract(&work).context("unzipping the IPA")?;
    let payload = work.join("Payload");
    let app = std::fs::read_dir(&payload)
        .context("the IPA has no Payload/ folder")?
        .flatten()
        .map(|e| e.path())
        .find(|p| p.is_dir() && p.extension().is_some_and(|e| e == "app"))
        .ok_or_else(|| anyhow!("no .app inside Payload/"))?;
    Ok(Unpacked { work, app })
}

/// Zip a .app back into an IPA (`Payload/<name>.app/...`).
pub fn pack(app: &Path, out: &Path) -> Result<()> {
    let name = app.file_name().ok_or_else(|| anyhow!("bad app path"))?.to_string_lossy().to_string();
    let mut zip = zip::ZipWriter::new(File::create(out)?);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    let mut buf = Vec::new();
    for entry in WalkDir::new(app).min_depth(1) {
        let entry = entry?;
        let rel = entry.path().strip_prefix(app)?.to_string_lossy().replace('\\', "/");
        let arc = format!("Payload/{name}/{rel}");
        if entry.file_type().is_dir() {
            zip.add_directory(format!("{arc}/"), options)?;
        } else {
            buf.clear();
            File::open(entry.path())?.read_to_end(&mut buf)?;
            zip.start_file(arc, options)?;
            zip.write_all(&buf)?;
        }
    }
    zip.finish()?;
    Ok(())
}

fn info_plists(app: &Path) -> Vec<PathBuf> {
    let mut plists = vec![app.join("Info.plist")];
    for entry in WalkDir::new(app).min_depth(1).into_iter().flatten() {
        if entry.file_type().is_dir() && entry.path().extension().is_some_and(|e| e == "appex") {
            plists.push(entry.path().join("Info.plist"));
        }
    }
    plists.into_iter().filter(|p| p.exists()).collect()
}

fn edit_plist(path: &Path, edit: impl FnOnce(&mut plist::Dictionary) -> bool) -> Result<bool> {
    let mut value: plist::Value = plist::from_file(path).with_context(|| format!("reading {}", path.display()))?;
    let dict = value.as_dictionary_mut().ok_or_else(|| anyhow!("{} is not a dictionary", path.display()))?;
    if !edit(dict) {
        return Ok(false);
    }
    plist::to_writer_binary(File::create(path)?, &value)?;
    Ok(true)
}

pub fn bundle_id(app: &Path) -> Result<String> {
    let value: plist::Value = plist::from_file(app.join("Info.plist"))?;
    value
        .as_dictionary()
        .and_then(|d| d.get("CFBundleIdentifier"))
        .and_then(|v| v.as_string())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("Info.plist has no CFBundleIdentifier"))
}

/// Replace the bundle id prefix `from` with `to` in the app and its extensions
/// (`a.b.app` -> `x.y`, `a.b.app.Share` -> `x.y.Share`).
pub fn replace_bundle_id(app: &Path, from: &str, to: &str) -> Result<usize> {
    let mut changed = 0;
    for path in info_plists(app) {
        let done = edit_plist(&path, |dict| {
            let Some(current) = dict.get("CFBundleIdentifier").and_then(|v| v.as_string()) else { return false };
            if current != from && !current.starts_with(&format!("{from}.")) {
                return false;
            }
            let new = format!("{to}{}", &current[from.len()..]);
            dict.insert("CFBundleIdentifier".into(), new.into());
            true
        })?;
        changed += done as usize;
    }
    Ok(changed)
}

/// Set the home-screen name.
pub fn set_display_name(app: &Path, name: &str) -> Result<()> {
    edit_plist(&app.join("Info.plist"), |dict| {
        dict.insert("CFBundleDisplayName".into(), name.into());
        true
    })?;
    Ok(())
}
