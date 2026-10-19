//! Apple ID sign-in and code signing with a free (Personal Team) account, via isideload.
//!
//! Signing prefers the offline path: every online signing caches the provisioning profile it used, and
//! while that profile is valid (7 days) the same app ID can be re-signed with the cached certificate key,
//! with no Apple contact at all.
//!
//! When Apple is needed, appman resumes the last session before it ever sends a password: the session
//! Apple issued at the last sign-in (its identity token and session key) and the short-lived Xcode token
//! derived from it are kept in the OS keychain. Only when Apple rejects both does a full sign-in (password,
//! and a 2FA code if Apple asks) happen, through a guard, because Apple locks accounts that see repeated
//! failed or unusual logins.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use der::Decode;
use isideload::anisette::remote_v3::RemoteV3AnisetteProvider;
use isideload::auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse};
use isideload::dev::certificates::DevelopmentCertificate;
use isideload::dev::developer_session::DeveloperSession;
use isideload::sideload::SideloaderBuilder;
use isideload::sideload::builder::MaxCertsBehavior;
use isideload::util::callbacks::MaxCertsCallbackFuture;
use isideload::util::fs_storage::FsStorage;
use isideload::util::keyring_storage::KeyringStorage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{self, Config};
use crate::ipa;

/// `MaxCertsBehavior<C>` cannot infer `C` from `Revoke` alone, so name a concrete callback type.
type RevokeCallback = fn(Vec<DevelopmentCertificate>) -> MaxCertsCallbackFuture;

fn report(e: rootcause::Report) -> anyhow::Error {
    anyhow!("{e:?}")
}

// ---------------------------------------------------------------------------------------------
// Sign-in guard

#[derive(Default, Serialize, Deserialize)]
struct Ledger {
    /// Unix seconds of failed sign-ins, most recent last.
    failures: Vec<u64>,
    /// Set when Apple reported the account locked; cleared by `--force` after the user unlocks it.
    locked: bool,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Ledger {
    fn load() -> Ledger {
        config::path("signin-ledger.json")
            .ok()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self) {
        if let Ok(path) = config::path("signin-ledger.json") {
            let _ = std::fs::write(path, serde_json::to_vec_pretty(self).unwrap_or_default());
        }
    }

    /// Refuse a sign-in that would likely make things worse.
    fn check(&mut self, force: bool) -> Result<()> {
        let day_ago = now().saturating_sub(24 * 3600);
        self.failures.retain(|t| *t > day_ago);
        if force {
            self.locked = false;
            return Ok(());
        }
        if self.locked {
            bail!(
                "Apple reported this account locked. Unlock it (iPhone Settings or iforgot.apple.com), \
                 then retry with --force."
            );
        }
        if let Some(last) = self.failures.last() {
            let wait = 3600u64.saturating_sub(now().saturating_sub(*last));
            if wait > 0 {
                bail!("the last sign-in failed; wait {} min before another (or pass --force)", wait.div_ceil(60));
            }
        }
        if self.failures.len() >= 3 {
            bail!("3 failed sign-ins in 24 h; Apple may lock the account. Wait, or pass --force.");
        }
        Ok(())
    }
}

/// The status lines `appman status` shows for the guard.
pub fn guard_status() -> String {
    let mut ledger = Ledger::load();
    match ledger.check(false) {
        Ok(()) => "sign-in allowed".to_string(),
        Err(e) => format!("sign-in blocked: {e}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Secrets

pub fn store_password(cfg: &Config, password: &str) -> Result<()> {
    keyring::Entry::new(&cfg.keyring_service, &cfg.apple_id()?)?
        .set_password(password)
        .context("saving the password in the OS keychain")
}

pub fn has_password(cfg: &Config) -> bool {
    password(cfg).is_ok()
}

fn password(cfg: &Config) -> Result<String> {
    keyring::Entry::new(&cfg.keyring_service, &cfg.apple_id()?)?
        .get_password()
        .context("no saved Apple ID password; run `appman setup`")
}

/// The development certificate's private key, cached by isideload in the keychain after a sign-in.
fn signing_key(cfg: &Config) -> Result<rsa::RsaPrivateKey> {
    use rsa::pkcs8::DecodePrivateKey;
    let email_hash = hex::encode(Sha256::digest(cfg.apple_id()?.as_bytes()));
    let der = keyring::Entry::new(&cfg.keyring_service, &format!("{email_hash}/key"))?
        .get_secret()
        .context("no cached signing key yet; the first signing needs an Apple sign-in")?;
    rsa::RsaPrivateKey::from_pkcs8_der(&der).context("decoding the cached signing key")
}

// ---------------------------------------------------------------------------------------------
// Sign-in

fn two_factor(
    _params: TwoFactorCallbackParams,
) -> impl std::future::Future<Output = Result<TwoFactorCallbackResponse, rootcause::Report>> + Send {
    async move {
        // Apple pushes the code to trusted devices by itself; asking it to send again is refused (403)
        // for many accounts, so only submit. Agents can drop the code into $APPMAN_2FA_FILE.
        if let Ok(path) = std::env::var("APPMAN_2FA_FILE") {
            eprintln!("Waiting for the verification code in {path} (15 min)...");
            for _ in 0..900 {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    let code = text.trim().to_string();
                    if !code.is_empty() {
                        let _ = std::fs::remove_file(&path);
                        return Ok(TwoFactorCallbackResponse::SubmitCode(code));
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
        eprintln!("Apple sent a 6-digit code to your trusted devices (iPhone, iPad or Mac): tap Allow there,");
        eprintln!("then type the code here. No device? Wait for the SMS option Apple offers after a while.");
        eprint!("Verification code: ");
        let mut code = String::new();
        let _ = std::io::stdin().read_line(&mut code);
        Ok(TwoFactorCallbackResponse::SubmitCode(code.trim().to_string()))
    }
}

/// The anisette server appman uses (the configured one, else isideload's default).
pub fn anisette_server(cfg: &Config) -> String {
    cfg.anisette.clone().unwrap_or_else(|| isideload::anisette::remote_v3::DEFAULT_ANISETTE_V3_URL.to_string())
}

/// The anisette provider, keeping one machine identity per server: an identity minted by one server is
/// rejected when sent via another. A stable identity is also what lets Apple recognise this "device" and
/// skip 2FA on later sign-ins.
fn anisette_provider(cfg: &Config) -> Result<RemoteV3AnisetteProvider> {
    let server = anisette_server(cfg);
    let host = server.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/').replace(['/', ':'], "_");
    Ok(RemoteV3AnisetteProvider::default()
        .map_err(report)?
        .set_serial_number("0".to_string())
        .set_url(&server)
        .set_storage(Box::new(FsStorage::new(config::path("anisette")?.join(host)))))
}

/// What Apple issued at the last sign-in, kept in the OS keychain so later runs resume instead of signing in.
#[derive(Serialize, Deserialize)]
struct SavedSession {
    /// The session plist (adsid, identity token, session key), as binary plist.
    spd: Vec<u8>,
    /// The Xcode token derived from it: (token, expiry in ms since the epoch).
    xcode: Option<(String, u64, u64)>,
}

fn session_entry(cfg: &Config) -> Result<keyring::Entry> {
    let email_hash = hex::encode(Sha256::digest(cfg.apple_id()?.as_bytes()));
    Ok(keyring::Entry::new(&cfg.keyring_service, &format!("{email_hash}/appman-session"))?)
}

fn load_session(cfg: &Config) -> Option<SavedSession> {
    serde_json::from_slice(&session_entry(cfg).ok()?.get_secret().ok()?).ok()
}

fn save_session(cfg: &Config, session: &SavedSession) {
    if let (Ok(entry), Ok(bytes)) = (session_entry(cfg), serde_json::to_vec(session)) {
        let _ = entry.set_secret(&bytes);
    }
}

pub fn forget_session(cfg: &Config) {
    if let Ok(entry) = session_entry(cfg) {
        let _ = entry.delete_credential();
    }
}

/// When the saved session's Xcode token expires (None when there is no saved session).
pub fn saved_session_status(cfg: &Config) -> Option<Option<SystemTime>> {
    let saved = load_session(cfg)?;
    Some(saved.xcode.map(|(_, _, expiry)| ms_to_time(expiry)))
}

fn ms_to_time(expiry: u64) -> SystemTime {
    // Apple reports token expiry in milliseconds since the epoch.
    let secs = if expiry > 10_000_000_000 { expiry / 1000 } else { expiry };
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn spd_bytes(spd: &plist::Dictionary) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, spd).ok()?;
    Some(out)
}

/// A developer-services session: from the cached Xcode token, else by resuming the saved session, else by
/// signing in. Whatever Apple issues is saved for next time.
pub async fn developer_session(cfg: &Config, force: bool) -> Result<DeveloperSession> {
    let email = cfg.apple_id()?;
    if let Some(saved) = load_session(cfg) {
        let mut account = AppleAccount::builder(&email).anisette_provider(anisette_provider(cfg)?).build().await.map_err(report)?;
        let spd: Option<plist::Dictionary> = plist::from_bytes(&saved.spd).ok();
        let adsid = spd.as_ref().and_then(|d| d.get("adsid")).and_then(|v| v.as_string()).map(str::to_string);
        if let (Some((token, duration, expiry)), Some(adsid)) = (saved.xcode.clone(), adsid.clone())
            && ms_to_time(expiry) > SystemTime::now() + Duration::from_secs(600)
        {
            eprintln!("Using the saved Apple session (no sign-in).");
            let token = isideload::auth::apple_account::AppToken { token, duration, expiry };
            return Ok(DeveloperSession::new(token, adsid, account.grandslam_client.clone(), account.anisette_generator.clone()));
        }
        account.spd = spd;
        match account.get_app_token("xcode.auth").await {
            Ok(token) => {
                eprintln!("Resumed the saved Apple session (no password, no 2FA).");
                save_session(cfg, &SavedSession { spd: saved.spd.clone(), xcode: Some((token.token.clone(), token.duration, token.expiry)) });
                let adsid = adsid.ok_or_else(|| anyhow!("saved session has no adsid"))?;
                return Ok(DeveloperSession::new(token, adsid, account.grandslam_client.clone(), account.anisette_generator.clone()));
            }
            Err(e) => eprintln!("The saved Apple session is no longer accepted ({}); signing in again.", short(&format!("{e:?}"))),
        }
    }
    let mut account = sign_in(cfg, force).await?;
    let session = DeveloperSession::from_account(&mut account).await.map_err(report)?;
    if let Some(spd) = account.spd.as_ref().and_then(spd_bytes) {
        let token = account.get_app_token("xcode.auth").await.ok();
        save_session(cfg, &SavedSession { spd, xcode: token.map(|t| (t.token, t.duration, t.expiry)) });
        eprintln!("Saved the Apple session in the keychain; the next runs resume it instead of signing in.");
    }
    Ok(session)
}

fn short(text: &str) -> String {
    text.lines().next().unwrap_or(text).chars().take(160).collect()
}

async fn sign_in(cfg: &Config, force: bool) -> Result<AppleAccount> {
    let mut ledger = Ledger::load();
    ledger.check(force)?;
    let email = cfg.apple_id()?;
    let password = password(cfg)?;
    let provider = anisette_provider(cfg)?;

    eprintln!("Signing in to Apple as {email} (password from the keychain)...");
    match AppleAccount::builder(&email).anisette_provider(provider).login(&password, two_factor).await {
        Ok(account) => {
            ledger.failures.clear();
            ledger.save();
            Ok(account)
        }
        Err(e) => {
            let text = format!("{e:?}");
            ledger.failures.push(now());
            ledger.locked |= text.contains("-20209") || text.contains("locked");
            ledger.save();
            Err(anyhow!("Apple sign-in failed:\n{text}"))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Profiles

fn profiles_dir() -> Result<PathBuf> {
    let dir = config::path("profiles")?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub struct ProfileInfo {
    /// `<TEAM>.<bundle id>`
    pub app_id: String,
    pub team: String,
    pub expires: SystemTime,
    pub bytes: Vec<u8>,
}

impl ProfileInfo {
    pub fn read(path: &Path) -> Result<ProfileInfo> {
        let bytes = std::fs::read(path)?;
        let dict = profile_dict(&bytes)?;
        let app_id = dict
            .get("Entitlements")
            .and_then(|v| v.as_dictionary())
            .and_then(|d| d.get("application-identifier"))
            .and_then(|v| v.as_string())
            .ok_or_else(|| anyhow!("profile has no application-identifier"))?
            .to_string();
        let team = app_id.split('.').next().unwrap_or_default().to_string();
        let expires = dict
            .get("ExpirationDate")
            .and_then(|v| v.as_date())
            .map(SystemTime::from)
            .unwrap_or(UNIX_EPOCH);
        Ok(ProfileInfo { app_id, team, expires, bytes })
    }

    /// The bundle id this profile signs, with the team suffix free accounts add (`<base>.<TEAM>`).
    pub fn bundle_id(&self) -> &str {
        &self.app_id[self.team.len() + 1..]
    }

    pub fn valid_for(&self, margin: Duration) -> bool {
        self.expires > SystemTime::now() + margin
    }
}

fn profile_dict(bytes: &[u8]) -> Result<plist::Dictionary> {
    let start = bytes.windows(5).position(|w| w == b"<?xml").ok_or_else(|| anyhow!("not a provisioning profile"))?;
    let end = bytes.windows(8).position(|w| w == b"</plist>").ok_or_else(|| anyhow!("truncated profile"))? + 8;
    plist::from_bytes::<plist::Value>(&bytes[start..end])?
        .into_dictionary()
        .ok_or_else(|| anyhow!("profile plist is not a dictionary"))
}

pub fn cached_profiles() -> Result<Vec<ProfileInfo>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(profiles_dir()?)?.flatten() {
        if let Ok(info) = ProfileInfo::read(&entry.path()) {
            out.push(info);
        }
    }
    out.sort_by(|a, b| a.app_id.cmp(&b.app_id));
    Ok(out)
}

/// A cached profile for `base_id` that is still valid for at least an hour.
pub fn usable_profile(base_id: &str) -> Result<Option<ProfileInfo>> {
    Ok(cached_profiles()?.into_iter().find(|p| {
        p.valid_for(Duration::from_secs(3600)) && (p.bundle_id() == format!("{base_id}.{}", p.team) || p.bundle_id() == base_id)
    }))
}

pub fn cache_profile(bytes: &[u8]) -> Result<()> {
    let dict = profile_dict(bytes)?;
    let app_id = dict
        .get("Entitlements")
        .and_then(|v| v.as_dictionary())
        .and_then(|d| d.get("application-identifier"))
        .and_then(|v| v.as_string())
        .ok_or_else(|| anyhow!("profile has no application-identifier"))?;
    std::fs::write(profiles_dir()?.join(format!("{app_id}.mobileprovision")), bytes)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Signing

/// Sign online: sign in, register the app ID if needed, fetch a profile, sign. Caches the profile.
///
/// The development certificate is reused while its key is in the keychain. A free account holds two; when
/// both are taken by other machines or tools, appman stops rather than revoke one (revoking breaks every
/// app that certificate signed) unless `revoke_cert` is set.
pub async fn sign_online(cfg: &Config, app: &Path, out: &Path, udid: &str, force: bool, revoke_cert: bool) -> Result<()> {
    let session = developer_session(cfg, force).await?;
    let behavior = if revoke_cert { MaxCertsBehavior::<RevokeCallback>::Revoke } else { MaxCertsBehavior::<RevokeCallback>::Error };
    let mut sideloader = SideloaderBuilder::new(session, cfg.apple_id()?)
        .machine_name(cfg.machine_name.clone())
        .storage(Box::new(KeyringStorage::new(cfg.keyring_service.clone())))
        .max_certs_behavior(behavior)
        .build();
    let staged = out.with_extension("unsigned.ipa");
    ipa::pack(app, &staged)?;
    let progress = |f: f32| {
        eprint!("\r  signing {:.0}%", f * 100.0);
        std::future::ready(())
    };
    let result = sideloader.sign_app(staged.clone(), None, true, Some(progress), None, Some(udid)).await;
    let _ = std::fs::remove_file(&staged);
    let (signed, _) = result.map_err(report).map_err(|e| {
        let text = format!("{e:#}");
        if text.to_lowercase().contains("certificate") && (text.contains("maximum") || text.contains("max")) {
            anyhow!("{text}\n\nBoth development certificates of this Apple ID are in use (other PCs or tools). \
                     Re-run with --revoke-cert to replace one; apps that certificate signed stop launching.")
        } else if text.contains("-36607") || text.to_lowercase().contains("maximum number of apps") {
            anyhow!("{text}\n\nFree Apple IDs may register 10 new app IDs per 7 days. Reuse an existing slot (`appman status`).")
        } else {
            e
        }
    }).context("signing failed")?;
    eprintln!();
    if let Ok(bytes) = std::fs::read(signed.join("embedded.mobileprovision")) {
        cache_profile(&bytes)?;
    }
    ipa::pack(&signed, out)
}

/// Sign offline with a cached profile and the cached certificate key: no Apple contact at all.
pub async fn sign_offline(cfg: &Config, app: &Path, out: &Path, profile: &ProfileInfo) -> Result<()> {
    use isideload::dev::app_ids::Profile;
    use isideload::dev::teams::DeveloperTeam;
    use isideload::sideload::application::Application;
    use isideload::sideload::cert_identity::CertificateIdentity;

    let dict = profile_dict(&profile.bytes)?;
    let leaf = dict
        .get("DeveloperCertificates")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_data())
        .ok_or_else(|| anyhow!("profile carries no certificate"))?;
    let identity = CertificateIdentity {
        machine_id: String::new(),
        machine_name: cfg.machine_name.clone(),
        private_key: signing_key(cfg)?,
        certificate: x509_cert::Certificate::from_der(leaf).context("decoding the profile certificate")?,
    };
    let text = |key: &str| dict.get(key).and_then(|v| v.as_string()).unwrap_or_default().to_string();
    let uuid = text("UUID");
    let name = text("Name");
    let isideload_profile = Profile {
        encoded_profile: plist::Data::new(profile.bytes.clone()),
        filename: format!("{uuid}.mobileprovision"),
        provisioning_profile_id: uuid.clone(),
        name,
        status: "active".to_string(),
        r#type: "iOS_App_Development".to_string(),
        distribution_method: "limited".to_string(),
        pro_pro_platorm: None,
        uuid,
        date_expire: dict.get("ExpirationDate").and_then(|v| v.as_date()).ok_or_else(|| anyhow!("no expiry"))?,
        managing_app: None,
        app_id_id: String::new(),
        is_template_profile: false,
        is_team_profile: Some(false),
        is_free_provisioning_profile: Some(true),
    };
    let team = DeveloperTeam { name: Some("Personal Team".to_string()), team_id: profile.team.clone(), r#type: None, status: None };

    let mut application = Application::new(app.to_path_buf()).map_err(report)?;
    let progress = |f: f32| {
        eprint!("\r  signing {:.0}%", f * 100.0);
        std::future::ready(())
    };
    isideload::sideload::sign::sign(&mut application, &identity, &isideload_profile, &mut Vec::new(), &None, &team, Some(progress))
        .await
        .map_err(report)
        .context("signing failed")?;
    eprintln!();
    ipa::pack(app, out)
}
