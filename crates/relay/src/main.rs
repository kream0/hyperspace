use std::io::{self, Write as _};
use std::net::SocketAddr;
use std::path::PathBuf;

use hyperspace_relay::{read_allow_file, Allow, Config, Rate, DEFAULT_LISTEN};

const HELP: &str = "\
hyperspace-relay - relay for hyperspace hosts and clients that cannot reach each other over UDP

Hosts and clients connect to it with a WebSocket and it forwards their
encrypted datagrams; it never holds a pairing key. It speaks plain HTTP:
put a TLS reverse proxy in front of it, on the same machine. The proxy must
append the client's address to X-Forwarded-For (nginx:
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for) or set it to
that address: the relay logs the header's last entry for connections from
loopback.

USAGE:
    hyperspace-relay --allow <FILE> [OPTIONS]

OPTIONS:
    --listen <ADDR:PORT>  Address to listen on [default: 127.0.0.1:47800]
    --allow <FILE>        Rooms allowed to use the relay: one room id (64 hex digits)
                          per line, '#' starts a comment. Read again on every connection,
                          so edits apply without a restart
    --open                Allow every room (for tests only; instead of --allow)
    --max-rooms <N>       Rooms open at once [default: 16]. Worst case: each room
                          more takes about 1 MiB of memory per seat (5 MiB with
                          4 clients per room)
    --max-clients <N>     Clients per room [default: 4]. Worst case: each client
                          more takes about 1 MiB of memory per room (16 MiB with
                          16 rooms). The relay prints its worst case as it starts
    --rate-mbit <N>       Limit per room and direction, in Mbit/s; 0 = none [default: 60]
    -h, --help            Show this help
    -V, --version         Show version

ENDPOINTS:
    GET /health           200 \"hyperspace relay ok\"
    GET /                 Version; hosts online and clients too when asked
                          directly on this machine (not through the proxy)
    GET /v1               WebSocket for hosts and clients
";

/// Like eprintln!, but never panics (eprintln! does when stderr is gone).
macro_rules! say {
    ($($arg:tt)*) => {{
        let _ = writeln!(io::stderr(), $($arg)*);
    }};
}

fn parse_args() -> Result<(SocketAddr, Config), String> {
    let mut listen: SocketAddr = DEFAULT_LISTEN.parse().expect("valid default address");
    let mut allow_file: Option<PathBuf> = None;
    let mut open = false;
    let mut max_rooms = 16usize;
    let mut max_clients = 4usize;
    let mut rate_mbit = 60u64;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = |name: &str| args.next().ok_or(format!("{name} needs a value"));
        match a.as_str() {
            "-h" | "--help" => {
                let _ = io::stdout().write_all(HELP.as_bytes());
                std::process::exit(0);
            }
            "-V" | "--version" => {
                let _ = writeln!(io::stdout(), "hyperspace-relay {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--listen" => {
                listen = val("--listen")?.parse().map_err(|_| "invalid --listen (expected ADDR:PORT)")?
            }
            "--allow" => allow_file = Some(val("--allow")?.into()),
            "--open" => open = true,
            "--max-rooms" => max_rooms = val("--max-rooms")?.parse().map_err(|_| "invalid --max-rooms")?,
            "--max-clients" => max_clients = val("--max-clients")?.parse().map_err(|_| "invalid --max-clients")?,
            "--rate-mbit" => rate_mbit = val("--rate-mbit")?.parse().map_err(|_| "invalid --rate-mbit")?,
            other => return Err(format!("unknown option '{other}' (see --help)")),
        }
    }
    let allow = match (allow_file, open) {
        (Some(_), true) => return Err("use either --allow or --open, not both".into()),
        (Some(path), false) => Allow::File(path),
        (None, true) => Allow::Open,
        (None, false) => return Err("--allow <FILE> is required (or --open, for tests only); see --help".into()),
    };
    let mut config = Config::new(allow);
    config.max_rooms = max_rooms;
    config.max_clients = max_clients;
    config.rate = Rate::from_mbit(rate_mbit);
    Ok((listen, config))
}

fn main() {
    let (listen, config) = match parse_args() {
        Ok(v) => v,
        Err(e) => {
            say!("error: {e}");
            std::process::exit(2);
        }
    };
    // Read the allow list once now, so a wrong path fails at start rather
    // than on the first connection.
    let rooms = match &config.allow {
        Allow::Open => "open to every room".to_string(),
        Allow::File(path) => match read_allow_file(path) {
            Ok((ids, bad)) => {
                if bad > 0 {
                    say!("warning: {bad} line(s) of {} are not room ids and are ignored", path.display());
                }
                format!("{} room(s) allowed by {}", ids.len(), path.display())
            }
            Err(e) => {
                say!("error: cannot read the allow list {}: {e}", path.display());
                std::process::exit(1);
            }
        },
    };
    let rate = config.rate.map_or("no rate limit".to_string(), |r| format!("{r} per room and direction"));
    let limits = format!(
        "at most {} rooms, {} clients per room, {} connections, about {} MiB of memory, {rate}",
        config.max_rooms,
        config.max_clients,
        config.links(),
        config.worst_case_mib()
    );

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            say!("error: cannot start: {e}");
            std::process::exit(1);
        }
    };
    let result = runtime.block_on(async {
        let listener = hyperspace_relay::bind(listen)?;
        let addr = listener.local_addr()?;
        hyperspace_relay::log(format_args!(
            "hyperspace relay {} listening on {addr} ({rooms}; {limits})",
            env!("CARGO_PKG_VERSION")
        ));
        hyperspace_relay::serve(listener, config).await
    });
    if let Err(e) = result {
        say!("error: {e}");
        std::process::exit(1);
    }
}
