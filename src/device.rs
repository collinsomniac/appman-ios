//! Talking to the iPhone over its RemotePairing service (port 49152), which answers on any network the
//! phone is on, including Tailscale. Pair once, then every command opens an encrypted tunnel with a
//! userspace TCP stack and reaches device services through RemoteServiceDiscovery (RSD).

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use idevice::crashreportcopymobile::CrashReportCopyMobileClient;
use idevice::installation_proxy::InstallationProxyClient;
use idevice::remote_pairing::{RemotePairingClient, RpPairingFile, RpPairingSocket, connect_tls_psk_tunnel_native};
use idevice::rsd::RsdHandshake;
use idevice::tcp::handle::AdapterHandle;
use idevice::{IdeviceError, RsdService};

use crate::config::{self, Device};

const PAIRING_FILE: &str = "pairing.plist";

fn err(e: IdeviceError) -> anyhow::Error {
    anyhow!("{e:?}")
}

/// The name this computer pairs under; the phone lists it under trusted computers.
fn host_label() -> String {
    gethostname::gethostname().to_string_lossy().to_string()
}

async fn resolve(device: &Device) -> Result<SocketAddr> {
    tokio::net::lookup_host((device.host.as_str(), device.port))
        .await
        .with_context(|| format!("resolving {}", device.host))?
        .next()
        .ok_or_else(|| anyhow!("{} did not resolve", device.host))
}

async fn connect(addr: SocketAddr) -> Result<tokio::net::TcpStream> {
    tokio::time::timeout(std::time::Duration::from_secs(10), tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("timed out reaching {addr}: is the phone awake and on Tailscale?"))?
        .with_context(|| format!("connecting to {addr}"))
}

async fn ask_pin() -> String {
    eprint!("Enter the code shown on the iPhone: ");
    let mut pin = String::new();
    let _ = std::io::stdin().read_line(&mut pin);
    pin.trim().to_string()
}

/// Pair with the phone. It shows a code that the user types here once; afterwards it trusts this computer.
pub async fn pair(device: &Device) -> Result<()> {
    let addr = resolve(device).await?;
    let host = host_label();
    let mut pairing = RpPairingFile::generate(&host);
    let mut client = RemotePairingClient::new(RpPairingSocket::new(connect(addr).await?), &host);
    eprintln!("Pairing with {}: unlock the iPhone and watch for a code.", device.host);
    client.connect(&mut pairing, ask_pin).await.map_err(err).context("pairing failed")?;
    std::fs::write(config::path(PAIRING_FILE)?, pairing.to_bytes())?;
    Ok(())
}

/// First pairing over a USB cable, for phones that do not offer network pairing (iPhones). Needs Apple's
/// usbmuxd: iTunes' Apple Mobile Device Service on Windows, built in on macOS, `usbmuxd` on Linux.
/// The phone asks to Trust this computer, then shows a code. Returns the UDID.
pub async fn pair_usb() -> Result<String> {
    use idevice::core_device_proxy::CoreDeviceProxy;
    use idevice::usbmuxd::{Connection, UsbmuxdAddr, UsbmuxdConnection};
    use idevice::{IdeviceService, RemoteXpcClient};

    let mut mux = UsbmuxdConnection::default()
        .await
        .map_err(err)
        .context("usbmuxd is not running; on Windows install iTunes, on Linux install usbmuxd")?;
    let device = mux
        .get_devices()
        .await
        .map_err(err)?
        .into_iter()
        .find(|d| d.connection_type == Connection::Usb)
        .ok_or_else(|| anyhow!("no iPhone connected by USB; plug it in, unlock it, and tap Trust"))?;
    let provider = device.to_provider(UsbmuxdAddr::default(), "appman");
    let proxy = CoreDeviceProxy::connect(&provider)
        .await
        .map_err(err)
        .context("could not reach the phone's CoreDevice service; unlock it and tap Trust")?;
    let rsd_port = proxy.tunnel_info().server_rsd_port;
    let mut adapter = proxy.create_software_tunnel().map_err(err)?.to_async_handle();
    let rsd = RsdHandshake::new(adapter.connect(rsd_port).await.map_err(|e| anyhow!("{e}"))?).await.map_err(err)?;
    let service = rsd
        .services
        .get("com.apple.internal.dt.coredevice.untrusted.tunnelservice")
        .ok_or_else(|| anyhow!("the phone offers no tunnel service (iOS 17 or later is required)"))?;
    let mut xpc = RemoteXpcClient::new(adapter.connect(service.port).await.map_err(|e| anyhow!("{e}"))?)
        .await
        .map_err(err)?;
    xpc.do_handshake().await.map_err(err)?;
    let _ = xpc.recv_root().await.map_err(err)?;

    let host = host_label();
    let mut pairing = RpPairingFile::generate(&host);
    RemotePairingClient::new(xpc, &host).connect(&mut pairing, ask_pin).await.map_err(err).context("pairing failed")?;
    std::fs::write(config::path(PAIRING_FILE)?, pairing.to_bytes())?;
    Ok(device.udid)
}

/// Reuse a pairing made by pymobiledevice3 (`~/.pymobiledevice3/remote_<udid>.plist`) so a phone that is
/// already paired with this computer does not need pairing again.
pub fn import_pymobiledevice3(udid: &str) -> Result<()> {
    let source = dirs::home_dir()
        .context("no home directory")?
        .join(".pymobiledevice3")
        .join(format!("remote_{udid}.plist"));
    let record: plist::Dictionary = plist::from_file(&source).with_context(|| format!("reading {}", source.display()))?;
    // pymobiledevice3 identifies the host as uuid3(DNS, hostname) in upper case.
    let identifier = uuid::Uuid::new_v3(&uuid::Uuid::NAMESPACE_DNS, host_label().as_bytes())
        .to_string()
        .to_uppercase();
    let mut dict = plist::Dictionary::new();
    for key in ["public_key", "private_key"] {
        dict.insert(key.into(), record.get(key).cloned().ok_or_else(|| anyhow!("{key} missing in {}", source.display()))?);
    }
    dict.insert("identifier".into(), identifier.into());
    if let Some(irk) = record.get("peer_alt_irk") {
        dict.insert("alt_irk".into(), irk.clone());
    }
    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, &dict)?;
    RpPairingFile::from_bytes(&bytes).map_err(err)?;
    std::fs::write(config::path(PAIRING_FILE)?, bytes)?;
    Ok(())
}

/// An open tunnel to the phone with its service directory.
pub struct Session {
    pub adapter: AdapterHandle,
    pub rsd: RsdHandshake,
}

impl Session {
    pub async fn open(device: &Device) -> Result<Self> {
        let file = config::path(PAIRING_FILE)?;
        if !file.exists() {
            bail!("this computer is not paired with the iPhone yet; run `appman pair <host>`");
        }
        let mut pairing = RpPairingFile::from_bytes(&std::fs::read(&file)?).map_err(err)?;
        let addr = resolve(device).await?;
        let mut client = RemotePairingClient::new(RpPairingSocket::new(connect(addr).await?), &host_label());
        client
            .connect(&mut pairing, async || bail_pin())
            .await
            .map_err(err)
            .context("the iPhone rejected this computer's pairing; run `appman pair` again")?;

        let port = client.create_tcp_listener().await.map_err(err)?;
        let mut tunnel_addr = addr;
        tunnel_addr.set_port(port);
        let tunnel = connect_tls_psk_tunnel_native(connect(tunnel_addr).await?, client.encryption_key())
            .await
            .map_err(err)
            .context("opening the encrypted tunnel")?;
        let client_ip = tunnel.info.client_address.parse()?;
        let server_ip = tunnel.info.server_address.parse()?;
        let (mtu, rsd_port) = (tunnel.info.mtu as usize, tunnel.info.server_rsd_port);
        let mut adapter = idevice::tcp::adapter::Adapter::new(Box::new(tunnel.into_inner()), client_ip, server_ip);
        adapter.set_mss(mtu.saturating_sub(60));
        let mut adapter = adapter.to_async_handle();
        let stream = adapter.connect(rsd_port).await.map_err(|e| anyhow!("{e}"))?;
        let rsd = RsdHandshake::new(stream).await.map_err(err)?;
        Ok(Session { adapter, rsd })
    }

    pub fn udid(&self) -> Option<String> {
        self.rsd.properties.get("UniqueDeviceID").and_then(|v| v.as_string()).map(str::to_string)
    }

    pub async fn install(&mut self, ipa: &Path) -> Result<()> {
        idevice::utils::installation::install_package_rsd(&mut self.adapter, &mut self.rsd, ipa, None)
            .await
            .map_err(err)
            .context("the iPhone refused the install")
    }

    /// User-installed apps: (bundle id, display name, version).
    pub async fn apps(&mut self) -> Result<Vec<(String, String, String)>> {
        let mut proxy = InstallationProxyClient::connect_rsd(&mut self.adapter, &mut self.rsd).await.map_err(err)?;
        let apps = proxy.get_apps(Some("User"), None).await.map_err(err)?;
        let text = |info: &plist::Value, key: &str| {
            info.as_dictionary().and_then(|d| d.get(key)).and_then(|v| v.as_string()).unwrap_or("").to_string()
        };
        let mut rows: Vec<_> = apps
            .iter()
            .map(|(id, info)| {
                let name = Some(text(info, "CFBundleDisplayName")).filter(|s| !s.is_empty()).unwrap_or_else(|| text(info, "CFBundleName"));
                (id.clone(), name, text(info, "CFBundleShortVersionString"))
            })
            .collect();
        rows.sort();
        Ok(rows)
    }

    /// Crash reports whose file name contains `filter` (the app's executable name), newest last.
    pub async fn crash_reports(&mut self, filter: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let mut client = CrashReportCopyMobileClient::connect_rsd(&mut self.adapter, &mut self.rsd).await.map_err(err)?;
        let needle = filter.to_lowercase();
        let mut names: Vec<String> = client
            .ls(None)
            .await
            .map_err(err)?
            .into_iter()
            .filter(|n| n.to_lowercase().contains(&needle) && n.ends_with(".ips"))
            .collect();
        names.sort();
        let mut out = Vec::new();
        for name in names {
            let data = client.pull(name.clone()).await.map_err(err)?;
            out.push((name, data));
        }
        Ok(out)
    }
}

/// An existing pairing must verify without a PIN; asking for one means it is no longer trusted.
fn bail_pin() -> String {
    String::new()
}
