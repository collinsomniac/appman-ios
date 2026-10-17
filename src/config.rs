//! Settings (`config.toml`) and the local state directory.
//!
//! Everything lives under one folder: `%APPDATA%\appman` on Windows, `~/Library/Application Support/appman`
//! on macOS, `~/.config/appman` on Linux, or `$APPMAN_HOME` when set. Secrets (the Apple ID password and
//! the signing key) stay in the OS keychain, never in this folder.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Port of the iPhone's RemotePairing service (pairing and tunnels over Wi-Fi or Tailscale).
pub const REMOTE_PAIRING_PORT: u16 = 49152;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// Apple ID used for signing.
    pub apple_id: Option<String>,
    /// Keychain service holding the password and signing key. iloader users can point this at "iloader".
    #[serde(default = "default_keyring_service")]
    pub keyring_service: String,
    /// Name the development certificate is registered under. Reusing one avoids creating (and, when
    /// a free account's two are taken, revoking) certificates; iloader users set "iloader".
    #[serde(default = "default_machine_name")]
    pub machine_name: String,
    /// Anisette server; isideload's default when unset.
    pub anisette: Option<String>,
    pub device: Option<Device>,
    /// Named app ID slots: name -> base bundle id (without the team suffix).
    #[serde(default)]
    pub slots: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Device {
    /// Tailscale (or LAN) host name or address of the iPhone.
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Filled in from the device on first connect.
    pub udid: Option<String>,
}

fn default_keyring_service() -> String {
    "appman".to_string()
}

fn default_machine_name() -> String {
    "appman".to_string()
}

fn default_port() -> u16 {
    REMOTE_PAIRING_PORT
}

pub fn home() -> Result<PathBuf> {
    let dir = match std::env::var_os("APPMAN_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => dirs::config_dir().context("no config directory on this OS")?.join("appman"),
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

pub fn path(name: &str) -> Result<PathBuf> {
    Ok(home()?.join(name))
}

impl Config {
    pub fn load() -> Result<Self> {
        let file = path("config.toml")?;
        if !file.exists() {
            return Ok(Config {
                keyring_service: default_keyring_service(),
                machine_name: default_machine_name(),
                ..Default::default()
            });
        }
        let text = std::fs::read_to_string(&file)?;
        toml::from_str(&text).with_context(|| format!("parsing {}", file.display()))
    }

    pub fn save(&self) -> Result<()> {
        std::fs::write(path("config.toml")?, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn apple_id(&self) -> Result<String> {
        match &self.apple_id {
            Some(id) => Ok(id.to_lowercase()),
            None => bail!("no Apple ID configured; run `appman setup`"),
        }
    }

    pub fn device(&self) -> Result<&Device> {
        self.device.as_ref().context("no iPhone configured; run `appman pair <host>`")
    }

    /// `--as` accepts a slot name or a bundle id.
    pub fn resolve_slot(&self, target: &str) -> String {
        self.slots.get(target).cloned().unwrap_or_else(|| target.to_string())
    }
}
