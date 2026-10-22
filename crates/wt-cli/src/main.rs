//! `wt`: command-line front end. Same engine and store as the desktop and mobile apps.

use clap::{Parser, Subcommand};
use core_app::{App, Controller, ControllerConfig, HttpFetcher, UiState};
use core_engine::runner::Binaries;
use core_engine::Mode;
use core_keyring::KeyringStore;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "wt",
    version,
    about = "Unified VPN client: import any config, connect with one command"
)]
struct Cli {
    /// Data directory (default: per-user application data)
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Import configs from files, `-` (stdin) or text. Images are scanned for QR codes.
    Import {
        inputs: Vec<String>,
        #[arg(long, default_value = "")]
        group: String,
        /// Download subscription links found in the input without asking
        #[arg(long)]
        yes: bool,
    },
    /// List stored configs
    List,
    Rename {
        id: String,
        name: String,
    },
    Group {
        id: String,
        group: String,
    },
    Delete {
        id: String,
    },
    /// Connect and stay connected until Ctrl-C
    Connect {
        /// Config id, id prefix, or exact name
        target: String,
        /// Local SOCKS5 proxy on this port instead of a system tunnel (no privileges needed)
        #[arg(long)]
        proxy: Option<u16>,
        /// DNS server reached through the tunnel (repeatable)
        #[arg(long)]
        dns: Vec<String>,
        /// TCP endpoint used to prove the tunnel carries traffic
        #[arg(long, default_value = "1.1.1.1:443")]
        probe: SocketAddr,
    },
    /// Leak-protection rules (Linux nftables)
    Killswitch {
        #[command(subcommand)]
        action: KsCmd,
    },
    /// Check secure storage and helper programs
    Doctor,
}

#[derive(Subcommand)]
enum KsCmd {
    /// Print the rules without applying them
    Print {
        #[arg(long)]
        iface: String,
        #[arg(long)]
        server: Vec<IpAddr>,
        #[arg(long)]
        lan: bool,
    },
    On {
        #[arg(long)]
        iface: String,
        #[arg(long)]
        server: Vec<IpAddr>,
        #[arg(long)]
        lan: bool,
    },
    Off,
}

fn data_dir(cli: &Cli) -> PathBuf {
    if let Some(d) = &cli.data_dir {
        return d.clone();
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/woodward-tunnel")
    } else if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or(home)
            .join("woodward-tunnel")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"))
            .join("woodward-tunnel")
    }
}

fn open_app(cli: &Cli) -> Result<Arc<App>, String> {
    let store = KeyringStore::new("woodward-tunnel");
    store.probe().map_err(|e| format!("Secure storage is not available ({e}). Configs contain keys and are never stored in plain text. On Linux install and unlock a Secret Service provider (GNOME Keyring or KeePassXC)."))?;
    App::new(&data_dir(cli), Arc::new(store), Arc::new(HttpFetcher))
        .map(Arc::new)
        .map_err(|e| e.to_string())
}

fn print_report(r: &core_app::ImportReport) {
    println!("added {}, already present {}", r.added.len(), r.duplicates);
    for p in &r.added {
        println!(
            "  + {}  {}  ({})",
            &p.id[..8],
            p.name,
            p.protocol.display_name()
        );
    }
    for p in &r.problems {
        println!("  ! {}: {}", p.label, p.message);
    }
}

fn read_input(arg: &str) -> Vec<u8> {
    if arg == "-" {
        let mut b = Vec::new();
        let _ = std::io::stdin().take(8 * 1024 * 1024).read_to_end(&mut b);
        b
    } else if let Ok(b) = std::fs::read(arg) {
        b
    } else {
        arg.as_bytes().to_vec()
    }
}

fn resolve(app: &App, target: &str) -> Result<String, String> {
    let list = app.list().map_err(|e| e.to_string())?;
    let hits: Vec<_> = list
        .iter()
        .filter(|p| p.id == target || p.id.starts_with(target) || p.name == target)
        .collect();
    match hits.as_slice() {
        [one] => Ok(one.id.clone()),
        [] => Err(format!("no config matches '{target}' (see `wt list`)")),
        _ => Err(format!(
            "'{target}' matches {} configs; use a longer id",
            hits.len()
        )),
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    match &cli.cmd {
        Cmd::Killswitch { action } => return killswitch(action),
        Cmd::Doctor => return doctor(&cli),
        _ => {}
    }
    let app = open_app(&cli)?;
    let dir = data_dir(&cli);
    match cli.cmd {
        Cmd::Import { inputs, group, yes } => {
            if inputs.is_empty() {
                return Err("give a file, `-` for stdin, or the config text".into());
            }
            for i in inputs {
                let r = app
                    .import_bytes(&read_input(&i), &group)
                    .map_err(|e| e.to_string())?;
                print_report(&r);
                for url in &r.subscription_urls {
                    if yes {
                        match app.import_subscription(url, &group) {
                            Ok(r) => print_report(&r),
                            Err(e) => println!("  ! subscription download failed: {e}"),
                        }
                    } else {
                        println!("  ? subscription link found: {url}\n    rerun with --yes to download it (this makes a network request)");
                    }
                }
            }
        }
        Cmd::List => {
            let l = app.list().map_err(|e| e.to_string())?;
            if l.is_empty() {
                println!("no configs yet; try `wt import <file>`");
            }
            for p in l {
                println!(
                    "{}  {:<12} {:<10} {}:{}  {}",
                    &p.id[..8],
                    p.group,
                    p.protocol.display_name(),
                    p.host,
                    p.port,
                    p.name
                );
            }
        }
        Cmd::Rename { id, name } => app
            .rename(&resolve(&app, &id)?, &name)
            .map_err(|e| e.to_string())?,
        Cmd::Group { id, group } => app
            .set_group(&resolve(&app, &id)?, &group)
            .map_err(|e| e.to_string())?,
        Cmd::Delete { id } => app
            .delete(&resolve(&app, &id)?)
            .map_err(|e| e.to_string())?,
        Cmd::Connect {
            target,
            proxy,
            dns,
            probe,
        } => {
            let id = resolve(&app, &target)?;
            let mode = proxy
                .map(|p| Mode::Proxy { socks_port: p })
                .unwrap_or(Mode::Tun);
            let cfg = ControllerConfig {
                mode: mode.clone(),
                dns,
                bins: Binaries::discover(),
                probe,
                ready_timeout: Duration::from_secs(15),
                work_dir: dir.join("run"),
            };
            let c = Controller::spawn(app, cfg);
            let mut rx = c.status();
            c.connect(&id);
            let mut last = UiState::Idle;
            loop {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        c.disconnect();
                        let _ = tokio::time::timeout(Duration::from_secs(8), async { while rx.borrow().state != UiState::Idle { if rx.changed().await.is_err() { break; } } }).await;
                        println!("disconnected");
                        return Ok(());
                    }
                    r = rx.changed() => {
                        if r.is_err() { return Ok(()); }
                        let s = rx.borrow().clone();
                        if s.state != last {
                            last = s.state;
                            match s.state {
                                UiState::Connected => match mode { Mode::Proxy { socks_port } => println!("connected: SOCKS5 proxy on 127.0.0.1:{socks_port}"), Mode::Tun => println!("connected: system traffic is tunnelled") },
                                UiState::Failed => { println!("failed: {}", s.message.unwrap_or_default()); return Err("could not connect".into()); }
                                other => println!("{other:?}{}", s.message.map(|m| format!(" - {m}")).unwrap_or_default()),
                            }
                        }
                    }
                }
            }
        }
        Cmd::Killswitch { .. } | Cmd::Doctor => {}
    }
    Ok(())
}

fn ks(iface: &str, server: &[IpAddr], lan: bool) -> core_policy::KillSwitch {
    core_policy::KillSwitch {
        tun_iface: iface.into(),
        server_ips: server.to_vec(),
        allow_lan: lan,
    }
}

fn killswitch(a: &KsCmd) -> Result<(), String> {
    match a {
        KsCmd::Print { iface, server, lan } => {
            print!("{}", ks(iface, server, *lan).nftables().map_err(|e| e.to_string())?);
            Ok(())
        }
        #[cfg(target_os = "linux")]
        KsCmd::On { iface, server, lan } => ks(iface, server, *lan).apply().map_err(|e| e.to_string()),
        #[cfg(target_os = "linux")]
        KsCmd::Off => core_policy::KillSwitch::remove().map_err(|e| e.to_string()),
        #[cfg(not(target_os = "linux"))]
        _ => Err("applying rules from the CLI is only implemented on Linux; the desktop app applies the OS-specific rules".into()),
    }
}

fn doctor(cli: &Cli) -> Result<(), String> {
    println!("data dir: {}", data_dir(cli).display());
    match KeyringStore::new("woodward-tunnel").probe() {
        Ok(()) => println!("secure storage: ok"),
        Err(e) => println!("secure storage: UNAVAILABLE ({e})"),
    }
    let b = Binaries::discover();
    for (n, p) in [
        ("sing-box", &b.sing_box),
        ("awg-socks", &b.awg_socks),
        ("openvpn", &b.openvpn),
    ] {
        let ok = std::process::Command::new(p)
            .arg("version")
            .output()
            .is_ok()
            || std::process::Command::new(p)
                .arg("--version")
                .output()
                .is_ok();
        println!("{n}: {}", if ok { "found" } else { "missing" });
    }
    Ok(())
}
