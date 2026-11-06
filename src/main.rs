//! appman: sign and install iOS apps on your own iPhone with a free Apple ID, over Tailscale.

mod apple;
mod config;
mod device;
mod ipa;
mod library;

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use config::{Config, Device};
use device::Session;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Save your Apple ID (the password goes to the OS keychain).
    Setup {
        #[arg(long)]
        apple_id: Option<String>,
        /// Keychain service for the password and signing key ("iloader" reuses iloader's saved login).
        #[arg(long)]
        keyring_service: Option<String>,
        /// Certificate machine name to reuse ("iloader" for iloader users).
        #[arg(long)]
        machine_name: Option<String>,
        /// Anisette server URL (default: isideload's).
        #[arg(long)]
        anisette: Option<String>,
    },
    /// Pair with the iPhone at HOST (its Tailscale name, or LAN address). Pairs over the network if the
    /// phone allows it, otherwise use --usb once; afterwards everything works over Wi-Fi or Tailscale.
    Pair {
        host: String,
        /// Pair over a USB cable (needed once for iPhones; requires iTunes on Windows).
        #[arg(long)]
        usb: bool,
        #[arg(long, default_value_t = config::REMOTE_PAIRING_PORT)]
        port: u16,
        /// Reuse an existing pymobiledevice3 pairing for this UDID instead of pairing again.
        #[arg(long, value_name = "UDID")]
        import_pymobiledevice3: Option<String>,
    },
    /// Sign an IPA and install it on the iPhone.
    Deploy(SignArgs),
    /// Sign an IPA without installing it.
    Sign {
        #[command(flatten)]
        args: SignArgs,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Install an already signed IPA.
    Install { ipa: PathBuf },
    /// List the apps you installed on the iPhone.
    Apps,
    /// Remove an app from the iPhone (frees one of the three free-profile slots).
    Uninstall {
        /// Bundle id, or a slot name from `appman slot`.
        app: String,
    },
    /// Save the crash reports of an app (matched by its executable name) and print the newest.
    Crash {
        name: String,
        #[arg(long, default_value = "crashes")]
        out: PathBuf,
    },
    /// Name an app ID slot, so `--as <name>` can be used instead of the bundle id.
    Slot { name: String, bundle_id: String },
    /// Show the configuration, cached profiles and the sign-in guard.
    Status,
    /// Re-sign and reinstall the apps in the library whose profiles expire within DAYS (one Apple session for all).
    Refresh {
        #[arg(long, default_value_t = 2.0)]
        days: f64,
        /// Refresh every library app, whatever its expiry.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        force_signin: bool,
        #[arg(long)]
        revoke_cert: bool,
    },
    /// Check everything a deploy or refresh needs, without signing in, and say what is missing.
    Doctor,
    /// Forget the saved Apple session (the next online signing signs in again).
    Logout,
}

#[derive(clap::Args)]
struct SignArgs {
    ipa: PathBuf,
    /// Install under another app ID (a slot name or bundle id), replacing whatever uses it.
    #[arg(long = "as", value_name = "SLOT")]
    target: Option<String>,
    /// Home-screen name.
    #[arg(long)]
    name: Option<String>,
    /// Sign in to Apple even when a cached profile could sign offline.
    #[arg(long)]
    online: bool,
    /// Override the sign-in guard (after unlocking the account, or knowingly).
    #[arg(long)]
    force_signin: bool,
    /// Allow revoking a development certificate when both of the account's are taken (breaks the apps it signed).
    #[arg(long)]
    revoke_cert: bool,
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("APPMAN_LOG").unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    if let Err(e) = run(Cli::parse().command).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run(command: Command) -> Result<()> {
    let mut cfg = Config::load()?;
    match command {
        Command::Setup { apple_id, keyring_service, machine_name, anisette } => {
            let apple_id = match apple_id.or(cfg.apple_id.clone()) {
                Some(id) => id,
                None => prompt("Apple ID (email): ")?,
            };
            cfg.apple_id = Some(apple_id.trim().to_lowercase());
            if let Some(service) = keyring_service {
                cfg.keyring_service = service;
            }
            if let Some(name) = machine_name {
                cfg.machine_name = name;
            }
            if anisette.is_some() {
                cfg.anisette = anisette;
            }
            let password = rpassword::prompt_password("Apple ID password (leave empty to keep the saved one): ")?;
            if !password.is_empty() {
                apple::store_password(&cfg, &password)?;
            }
            cfg.save()?;
            println!("Saved. Next: `appman pair <iphone-tailscale-name>`.");
        }
        Command::Pair { host, usb, port, import_pymobiledevice3 } => {
            let mut dev = Device { host, port, udid: None };
            match (&import_pymobiledevice3, usb) {
                (Some(udid), _) => device::import_pymobiledevice3(udid)?,
                (None, true) => {
                    device::pair_usb().await?;
                    println!("Paired over USB; checking the network path to {}...", dev.host);
                }
                (None, false) => device::pair(&dev).await?,
            }
            let session = Session::open(&dev).await?;
            dev.udid = session.udid();
            println!("Paired with {} ({}).", dev.host, dev.udid.as_deref().unwrap_or("unknown UDID"));
            cfg.device = Some(dev);
            cfg.save()?;
        }
        Command::Deploy(args) => {
            let signed = std::env::temp_dir().join(format!("appman-signed-{}.ipa", std::process::id()));
            let target = sign(&mut cfg, &args, &signed).await?;
            let result = install(&cfg, &signed).await;
            let _ = std::fs::remove_file(&signed);
            result?;
            if let Err(e) = library::remember(&target, args.name.as_deref(), &args.ipa) {
                eprintln!("note: couldn't keep a copy for `appman refresh`: {e:#}");
            }
        }
        Command::Refresh { days, all, force_signin, revoke_cert } => refresh(&mut cfg, days, all, force_signin, revoke_cert).await?,
        Command::Doctor => doctor(&cfg).await,
        Command::Logout => {
            apple::forget_session(&cfg);
            println!("Forgot the saved Apple session.");
        }
        Command::Sign { args, out } => {
            sign(&mut cfg, &args, &out).await?;
            println!("Signed: {}", out.display());
        }
        Command::Install { ipa } => install(&cfg, &ipa).await?,
        Command::Apps => {
            let mut session = Session::open(cfg.device()?).await?;
            for (id, name, version) in session.apps().await? {
                println!("{id:50} {name:24} {version}");
            }
        }
        Command::Uninstall { app } => {
            // Accept a slot name so the thing you name in `--as <slot>` is the same
            // thing you name here; a raw bundle id passes through unchanged.
            let bundle = cfg.resolve_slot(&app);
            let mut session = Session::open(cfg.device()?).await?;
            session.uninstall(&bundle).await?;
            println!("Removed {bundle}.");
        }
        Command::Crash { name, out } => {
            let mut session = Session::open(cfg.device()?).await?;
            let reports = session.crash_reports(&name).await?;
            if reports.is_empty() {
                println!("No crash reports for '{name}'.");
                return Ok(());
            }
            std::fs::create_dir_all(&out)?;
            for (file, data) in &reports {
                std::fs::write(out.join(file.trim_start_matches('/')), data)?;
            }
            println!("Saved {} report(s) to {}.", reports.len(), out.display());
            if let Some((file, data)) = reports.last() {
                println!("\nNewest: {file}\n{}", summarize_crash(data));
            }
        }
        Command::Slot { name, bundle_id } => {
            cfg.slots.insert(name.clone(), bundle_id.clone());
            cfg.save()?;
            println!("Slot '{name}' = {bundle_id}");
        }
        Command::Status => status(&cfg),
    }
    Ok(())
}

fn prompt(question: &str) -> Result<String> {
    eprint!("{question}");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Sign `args.ipa` into `out`; returns the app ID it was signed as.
async fn sign(cfg: &mut Config, args: &SignArgs, out: &Path) -> Result<String> {
    let bundle = ipa::unpack(&args.ipa)?;
    let current = ipa::bundle_id(&bundle.app)?;
    let target = args.target.as_deref().map(|t| cfg.resolve_slot(t)).unwrap_or_else(|| current.clone());
    if let Some(name) = &args.name {
        ipa::set_display_name(&bundle.app, name)?;
    }

    let cached = if args.online { None } else { apple::usable_profile(&target)? };
    match cached {
        Some(profile) => {
            println!("Signing {target} offline with the cached profile (valid until {}).", ago_or_until(profile.expires));
            ipa::replace_bundle_id(&bundle.app, &current, profile.bundle_id())?;
            apple::sign_offline(cfg, &bundle.app, out, &profile).await?;
            Ok(target)
        }
        None => {
            if target != current {
                ipa::replace_bundle_id(&bundle.app, &current, &target)?;
            }
            let udid = match cfg.device()?.udid.clone() {
                Some(udid) => udid,
                None => Session::open(cfg.device()?).await?.udid().context("the iPhone did not report its UDID")?,
            };
            println!("No valid cached profile for {target}; signing online (registers the app ID if it is new).");
            apple::sign_online(cfg, &bundle.app, out, &udid, args.force_signin, args.revoke_cert).await?;
            Ok(target)
        }
    }
}

async fn install(cfg: &Config, ipa: &Path) -> Result<()> {
    let device = cfg.device()?;
    println!("Installing on {}...", device.host);
    let mut session = Session::open(device).await.map_err(device_hint)?;
    session.install(ipa).await?;
    println!("Installed.");
    Ok(())
}

/// Turn connection failures into what to do about them.
fn device_hint(e: anyhow::Error) -> anyhow::Error {
    let text = format!("{e:#}");
    if text.contains("10061") || text.contains("refused") {
        e.context("the iPhone refused the connection: unlock it (it only listens while unlocked) and keep it awake")
    } else if text.contains("timed out") || text.contains("10060") || text.contains("Timeout") {
        e.context("the iPhone didn't answer: check Tailscale is connected on both, and the phone is awake on Wi-Fi")
    } else {
        e
    }
}

/// Re-sign and reinstall library apps nearing expiry; the first needs Apple, the rest reuse its session.
async fn refresh(cfg: &mut Config, days: f64, all: bool, force_signin: bool, revoke_cert: bool) -> Result<()> {
    let margin = Duration::from_secs_f64(days * 86400.0);
    let entries = library::entries()?;
    if entries.is_empty() {
        println!("The library is empty: apps deployed with `appman deploy` are kept there for refreshing.");
        return Ok(());
    }
    let mut done = 0;
    for entry in entries {
        let due = all || apple::usable_profile(&entry.target)?.is_none_or(|p| !p.valid_for(margin));
        if !due {
            println!("{}: still valid, skipped", entry.target);
            continue;
        }
        println!("{}: refreshing", entry.target);
        let args = SignArgs {
            ipa: library::ipa_path(&entry.target)?,
            target: Some(entry.target.clone()),
            name: entry.name.clone(),
            online: true,
            force_signin,
            revoke_cert,
        };
        let signed = std::env::temp_dir().join(format!("appman-refresh-{}.ipa", std::process::id()));
        sign(cfg, &args, &signed).await?;
        let result = install(cfg, &signed).await;
        let _ = std::fs::remove_file(&signed);
        result?;
        done += 1;
    }
    println!("Refreshed {done} app(s).");
    Ok(())
}

/// Everything a deploy or refresh depends on, checked without signing in.
async fn doctor(cfg: &Config) {
    let ok = |b: bool| if b { "ok  " } else { "FIX " };
    let id = cfg.apple_id.clone();
    println!("{} apple id         {}", ok(id.is_some()), id.as_deref().unwrap_or("not set: run `appman setup`"));
    let has_password = id.is_some() && apple::has_password(cfg);
    println!("{} password         {}", ok(has_password), if has_password { "in the OS keychain" } else { "missing: run `appman setup` (only needed when a sign-in is)" });
    match apple::saved_session_status(cfg) {
        Some(Some(expiry)) if expiry > SystemTime::now() => println!("ok   apple session    saved; Xcode token valid {}", ago_or_until(expiry)),
        Some(_) => println!("ok   apple session    saved; token expired, will be renewed from the session (no password unless Apple refuses it)"),
        None => println!("--   apple session    none yet: the next online signing signs in once (password + maybe 2FA), then it's reused"),
    }
    println!("     sign-in guard    {}", apple::guard_status());
    let server = apple::anisette_server(cfg);
    let reachable = anisette_reachable(&server).await;
    println!("{} anisette         {server} {}", ok(reachable), if reachable { "(reachable)" } else { "(unreachable: set another with `appman setup --anisette <url>`, or run one locally)" });
    match &cfg.device {
        None => println!("FIX  iphone           not paired: run `appman pair <tailscale-name>`"),
        Some(d) => {
            let addr = format!("{}:{}", d.host, d.port);
            let state = match tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(&addr)).await {
                Ok(Ok(_)) => "ok   ".to_string() + &format!("iphone           {addr} reachable"),
                Ok(Err(e)) if e.to_string().contains("10061") || e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    format!("FIX  iphone           {addr} refused: unlock the iPhone (it only listens while unlocked)")
                }
                Ok(Err(e)) => format!("FIX  iphone           {addr}: {e}"),
                Err(_) => format!("FIX  iphone           {addr} timed out: is Tailscale connected on the phone and the PC?"),
            };
            println!("{state}");
        }
    }
    let profiles = apple::cached_profiles().unwrap_or_default();
    let library = library::entries().unwrap_or_default();
    for entry in &library {
        let profile = apple::usable_profile(&entry.target).ok().flatten();
        match profile {
            Some(p) => println!("ok   app              {} profile valid {}", entry.target, ago_or_until(p.expires)),
            None => println!("FIX  app              {} profile expired or missing: `appman refresh`", entry.target),
        }
    }
    if library.is_empty() {
        println!("--   library          empty (deploys are kept there for `appman refresh`)");
    }
    let valid = profiles.iter().filter(|p| p.valid_for(Duration::ZERO)).count();
    println!("     free account     {valid} app(s) with live profiles (iOS runs at most 3 free-signed apps at once); 10 new app IDs per 7 days");
}

async fn anisette_reachable(server: &str) -> bool {
    let url = format!("{}/v3/client_info", server.trim_end_matches('/'));
    let host = url.trim_start_matches("https://").trim_start_matches("http://");
    let host = host.split('/').next().unwrap_or(host);
    let port = if url.starts_with("https") { 443 } else { 80 };
    let addr = if host.contains(':') { host.to_string() } else { format!("{host}:{port}") };
    matches!(tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr)).await, Ok(Ok(_)))
}

fn ago_or_until(time: SystemTime) -> String {
    match time.duration_since(SystemTime::now()) {
        Ok(left) => format!("{} h from now", left.as_secs() / 3600),
        Err(_) => "expired".to_string(),
    }
}

/// The parts of an .ips crash report that usually explain the crash.
fn summarize_crash(data: &[u8]) -> String {
    let text = String::from_utf8_lossy(data);
    // .ips = one JSON header line, then the JSON report.
    let body = text.split_once('\n').map(|(_, b)| b).unwrap_or(&text);
    let Ok(report) = serde_json::from_str::<serde_json::Value>(body) else {
        return text.chars().take(2000).collect();
    };
    let mut lines = Vec::new();
    for key in ["exception", "termination", "asi"] {
        if let Some(v) = report.get(key) {
            lines.push(format!("{key}: {v}"));
        }
    }
    let images = report.get("usedImages").and_then(|v| v.as_array());
    let frames = |list: &serde_json::Value| -> Vec<String> {
        list.as_array()
            .into_iter()
            .flatten()
            .take(25)
            .map(|f| {
                let image = f
                    .get("imageIndex")
                    .and_then(|i| i.as_u64())
                    .and_then(|i| images.and_then(|im| im.get(i as usize)))
                    .and_then(|im| im.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("?");
                format!("  {image:24} {}", f.get("symbol").and_then(|s| s.as_str()).unwrap_or("?"))
            })
            .collect()
    };
    if let Some(bt) = report.get("lastExceptionBacktrace") {
        lines.push("last exception backtrace:".into());
        lines.extend(frames(bt));
    }
    let faulting = report.get("faultingThread").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    if let Some(thread) = report.get("threads").and_then(|t| t.get(faulting)) {
        lines.push(format!("crashed thread {faulting}:"));
        lines.extend(frames(thread.get("frames").unwrap_or(&serde_json::Value::Null)));
    }
    lines.join("\n")
}

fn status(cfg: &Config) {
    println!("config:       {}", config::path("config.toml").map(|p| p.display().to_string()).unwrap_or_default());
    println!("apple id:     {}", cfg.apple_id.as_deref().unwrap_or("(not set; run `appman setup`)"));
    println!("keychain:     service \"{}\", certificate name \"{}\"", cfg.keyring_service, cfg.machine_name);
    match &cfg.device {
        Some(d) => println!("iphone:       {}:{} {}", d.host, d.port, d.udid.as_deref().unwrap_or("")),
        None => println!("iphone:       (not paired; run `appman pair <host>`)"),
    }
    println!("sign-in:      {}", apple::guard_status());
    for (name, id) in &cfg.slots {
        println!("slot:         {name} = {id}");
    }
    match apple::cached_profiles() {
        Ok(profiles) if !profiles.is_empty() => {
            for p in profiles {
                let state = if p.valid_for(Duration::ZERO) { ago_or_until(p.expires) } else { "expired".into() };
                println!("profile:      {} ({state})", p.app_id);
            }
        }
        _ => println!("profile:      none cached yet"),
    }
}
