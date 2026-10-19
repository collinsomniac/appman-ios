//! The app library: every deploy keeps the unsigned IPA (and its home-screen name) under the app ID it was
//! installed as, so `appman refresh` can re-sign and reinstall everything before the 7-day profiles run out,
//! as AltStore and Sideloadly do.

use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config;

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    /// The app ID (bundle id) the app was installed as.
    pub target: String,
    /// The home-screen name it was given, if any.
    pub name: Option<String>,
    /// Where the IPA came from.
    pub source: String,
}

fn dir() -> Result<PathBuf> {
    let dir = config::path("library")?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn file_stem(target: &str) -> String {
    target.replace(['/', '\\', ':'], "_")
}

pub fn ipa_path(target: &str) -> Result<PathBuf> {
    Ok(dir()?.join(format!("{}.ipa", file_stem(target))))
}

/// Keep a copy of the unsigned IPA for `target`.
pub fn remember(target: &str, name: Option<&str>, ipa: &std::path::Path) -> Result<()> {
    std::fs::copy(ipa, ipa_path(target)?)?;
    let entry = Entry { target: target.to_string(), name: name.map(str::to_string), source: ipa.display().to_string() };
    std::fs::write(dir()?.join(format!("{}.json", file_stem(target))), serde_json::to_vec_pretty(&entry)?)?;
    Ok(())
}

pub fn entries() -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir()?)?.flatten() {
        if e.path().extension().is_some_and(|x| x == "json")
            && let Ok(entry) = serde_json::from_slice::<Entry>(&std::fs::read(e.path())?)
        {
            out.push(entry);
        }
    }
    out.sort_by(|a, b| a.target.cmp(&b.target));
    Ok(out)
}
