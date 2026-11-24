# hyperspace

A remote desktop built for one thing: the lowest possible latency between a
Windows machine and the Mac you are sitting at - on the same network or from
anywhere else. No accounts, no VPN: by default the client talks straight to
the host over one encrypted UDP flow. For networks that let no UDP through,
an optional relay that you run yourself carries the same encrypted traffic
over HTTPS.

- **Host**: Windows 10/11 (`hyperspace-host.exe`)
- **Client**: macOS 12+ on Apple Silicon or Intel (`hyperspace-client`)
- **Relay** (optional): Linux x64 (`hyperspace-relay`)

Both are written in Rust and talk directly to the platform APIs.

## Quick start

Grab both downloads from the [latest release](https://github.com/kream0/hyperspace/releases/latest).

**On the Windows machine**, unzip `hyperspace-host-windows-x64.zip` and run:

```powershell
.\hyperspace-host.exe
```

The binaries are not code-signed, so SmartScreen may show "Windows protected
your PC" the first time: choose *More info → Run anyway*. Windows then asks
once whether to allow it through the firewall: allow it (tick both private
and public networks if you want to connect from outside).

After a few seconds the host prints a pairing command:

```
hyperspace-client pair hs1.Ayut2jKD...Qc8.192.168.1.50/45800,203.0.113.7/45800
```

**On the Mac**, download and unpack from a terminal (this avoids the
Gatekeeper quarantine a browser download would get):

```bash
curl -L https://github.com/kream0/hyperspace/releases/latest/download/hyperspace-client-macos-universal.tar.gz | tar -xz
```

Paste the pairing command once (prefix it with `./`). From then on, wherever
you are:

```bash
./hyperspace-client
```

If you downloaded the client with a browser instead, clear the quarantine
flag first:

```bash
xattr -d com.apple.quarantine hyperspace-client
```

The first connection makes macOS ask whether your terminal may access devices
on the local network: allow it.

Closing the window (or `Ctrl+Option+Cmd+Q`) disconnects cleanly: the host
stops capturing, releases any keys still held, and waits for the next
connection.

## Connecting from outside your network

The host makes itself reachable; there is nothing to install or configure in
between.

1. **It opens the door.** On start the host asks your router (UPnP) to forward
   its UDP port, and to open its IPv6 firewall where the router supports that.
   The host log says plainly whether this worked and which public address it
   got.
2. **The client knows every way in.** The pairing string carries the host's
   LAN address, its public address and its IPv6 addresses. The client tries
   all of them at once and uses whichever answers first - so the same command
   works at home and away.
3. **It survives address changes.** Home connections get a new public IP
   every so often. The host keeps its current addresses published in the
   BitTorrent DHT - a public, server-less lookup network - encrypted and signed
   with keys derived from your pairing key, so only your client can read or
   update them. When the known addresses do not answer, the client looks the
   current ones up and remembers them. (`--no-dht` on the host / `--no-lookup`
   on the client turn this off; `--public-host my.name.example` adds a DNS
   name instead.)
4. **It adapts to the link.** Across the internet the stream starts at
   10 Mbit/s with smaller packets, and the client continuously asks the host
   for more or less as the path allows, reacting to rising delay before it
   becomes visible.

What can still stop it:

| Situation | What the host log says | What to do |
| --- | --- | --- |
| Router has UPnP switched off | "automatic port forwarding is unavailable" | Enable UPnP, or forward UDP 45800 to the PC by hand |
| Provider uses carrier-grade NAT (no public IPv4) | "its own address is not public" | Connect over IPv6 (both ends need it), use a [relay](#through-a-relay), or ask the provider for a public IPv4 |
| Windows Firewall blocks public networks | (client gets no answer) | Allow hyperspace-host for public networks |
| Network you are on blocks UDP | (client gets no answer) | Use a [relay](#through-a-relay), or another network / tethering |
| The Mac runs a VPN or a company security client | client error names the tunnel interface | Those route traffic through a tunnel that usually drops direct UDP. Use a [relay](#through-a-relay); if the relay's domain is blocked too, ask whoever manages the device (the IT department) |

On start the host also sends a test packet to its own public address. If it
comes back in, the log says so and you know the router and Windows Firewall
both let clients through; if not, the log gives the firewall command to run.
When a connection fails, the client lists each address it tried with the
most likely reason that one stayed silent.

## Through a relay

Some networks let no UDP out at all, for example a locked-down work laptop.
For those, host and client can both connect out to a relay, which pairs them
and passes their datagrams along.

Each end opens a WebSocket over TLS to the relay on port 443. To the network
this is an ordinary outbound HTTPS connection to the relay's name, and nothing
has to reach the PC or the Mac from outside. The relay never holds the pairing
key and sees only ciphertext: the session is the same end-to-end encrypted one
as on a direct path (see [Security](#security)).

Direct stays first. The client tries the host's own addresses, and if none
answers within 0.6 s the relay joins the race: whichever path answers first
carries the session. When a relayed session is lost, the client reconnects on
its own and tries the relay from the start. A relayed session takes a longer
path, over TCP, so use a relay only when direct does not work.

To pair through a relay:

1. On the PC, print the host's relay id and give it to whoever runs the relay
   (see [Running your own relay](#running-your-own-relay)):

   ```powershell
   .\hyperspace-host.exe --relay-id
   ```

2. Start the host with the relay once. It remembers it until `--relay off`:

   ```powershell
   .\hyperspace-host.exe --relay wss://relay.example.com/v1
   ```

   The pairing string it prints now ends with the relay:
   `hs1.<key>.<addr>/<port>,…,relay=wss://relay.example.com/v1`. Pair the Mac
   with it as usual.

A pairing made before 0.3.0 has no relay in it. Pair again with the new
string, or run the client once with the relay; the client keeps that setting,
and it takes precedence over the pairing string's relay:

```bash
./hyperspace-client --relay wss://relay.example.com/v1
```

`--relay off` turns the relay off again on either end. On either end,
`--relay-check wss://relay.example.com/v1` checks from the network it is on
that the relay answers (DNS, TCP, TLS, WebSocket), then exits.

If a company network blocks the relay's domain, ask the IT department to allow
it.

## Running your own relay

Each release includes `hyperspace-relay-linux-x64.tar.gz`: a static Linux x64
binary with no dependencies. It needs a server with a DNS name and a TLS
certificate for it.

The relay admits only the hosts on its allow list: a text file with one room
id (64 hex characters) per line, where `#` starts a comment. The relay reads
it again on every connection, so adding a host needs no restart. The line for
a host is what `hyperspace-host --relay-id` prints. The host calls this value
the *relay id*, the relay's `--allow` help calls it the *room id*: it is the
same value. It is derived from the pairing key but is not the key, and it
cannot be used to connect. It changes only with `--new-key`, after which the
host's line must be replaced.

The relay speaks plain HTTP on `127.0.0.1:47800`. Run it as its own
unprivileged user:

```bash
hyperspace-relay --allow /etc/hyperspace-relay/allow
```

Put a TLS reverse proxy in front of it, on the same machine, that forwards
WebSocket upgrades on `/v1`. With nginx, inside the `server` block for
`relay.example.com`:

```nginx
location /v1 {
    proxy_pass http://127.0.0.1:47800;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
location / {
    proxy_pass http://127.0.0.1:47800;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

Every location that reaches the relay must set `X-Forwarded-For`: the relay
logs that header's last entry as the peer's address. Through the proxy,
`https://relay.example.com/` is a status page that shows only the relay's
version, and `/health` answers `hyperspace relay ok`.

A minimal systemd unit:

```ini
[Service]
ExecStart=/usr/local/bin/hyperspace-relay --allow /etc/hyperspace-relay/allow
DynamicUser=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Limits and timers:

- Each room (one host and its clients, 4 at most by default) is limited to
  60 Mbit/s in each direction by default (`--rate-mbit`).
- Hosts and clients ping the relay every 15 s. The relay pings every 20 s and
  closes a link after 60 s of silence, well within the proxy timeouts above.
- The relay closes a WebSocket itself with one of three codes: 1008 when it
  refuses the connection (for example, a room not on the allow list), 4001
  when another host with the same key replaced this host, and 1000 when a
  host ends a client's connection normally.

## Security

Only a paired client can connect, and everything is encrypted.

- The pairing string contains a random 256-bit key. Host and client run a
  Noise `NNpsk0` handshake (ephemeral X25519 mixed with that key), then seal
  every packet - video, input, cursor - with ChaCha20-Poly1305, with replay
  protection. Each session has fresh keys; recorded traffic stays private
  even if the pairing key leaks later.
- The host answers nothing it cannot authenticate. To a port scanner it looks
  exactly like a closed port.
- There is no password to type, and none to guess: **the pairing string is
  the credential.** Treat it like an SSH private key. It is stored in
  `%APPDATA%\hyperspace` on the host and `~/.config/hyperspace` on the client.
  If it leaks, run `hyperspace-host --new-key` and pair again.
- A relay sees only ciphertext and room ids, never the pairing key: the
  pairing string stays the only secret.

### Client shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl+Option+Cmd+Q` | Disconnect and quit |
| `Ctrl+Option+Cmd+F` | Toggle fullscreen |
| `Ctrl+Option+Cmd+S` | Toggle the statistics in the title bar |

Keys are forwarded by physical position: `Control` is Ctrl, `Option` is Alt
and `Command` is the Windows key. Pass `--cmd-as-ctrl` if you would rather
have `Cmd+C` / `Cmd+V` act as `Ctrl+C` / `Ctrl+V`. System shortcuts that
macOS handles itself (`Cmd+Tab`, Mission Control, …) stay on the Mac.

### Options

```
hyperspace-client pair <PAIRING-STRING>
hyperspace-client [HOST[:PORT]] [--fps N] [--bitrate MBIT] [--codec h264|hevc]
                  [--fullscreen] [--cmd-as-ctrl] [--stats] [--no-lookup]
                  [--relay URL|off] [--relay-check URL]

hyperspace-host [--port N] [--bind ADDR:PORT] [--display N] [--codec h264|hevc]
                [--encoder auto|hw|sw] [--bitrate MBIT] [--max-fps N]
                [--view-only] [--once]
                [--public-host NAME] [--no-upnp] [--no-dht] [--new-key]
                [--relay URL|off] [--relay-id] [--relay-check URL]
                [--list] [--self-test]

hyperspace-relay --allow FILE [--listen ADDR:PORT] [--max-rooms N]
                 [--max-clients N] [--rate-mbit N]
```

- The client asks for its display's refresh rate (120 fps on a ProMotion
  panel); the host caps it at its own monitor's refresh rate.
- On the LAN the default bitrate scales with resolution (about 31 Mbit/s for
  1440p60, 70 Mbit/s for 4K60) and that is also the ceiling the automatic
  adaptation works under. `--bitrate` pins it.
- `hyperspace-client 192.168.1.50` connects to the paired host at one
  specific address.
- `hyperspace-host --list` shows displays and available encoders;
  `hyperspace-host --self-test` checks capture and encoding locally and
  prints how long a frame takes to encode.
- `--bind ADDR:PORT` makes the host listen on one address only (by default
  it listens on all, IPv4 and IPv6); `--once` makes it exit when the first
  session ends.
- `--relay URL` (`wss://...`) is remembered on both ends until `--relay off`;
  on the client it is used when the host's addresses do not answer.
  `--relay-check URL` checks that a relay can be reached, then exits.
  `hyperspace-host --relay-id` prints the line for the relay's allow list,
  then exits.
- `hyperspace-relay` listens on `127.0.0.1:47800` by default. `--max-rooms`
  (default 16) and `--max-clients` (clients per room, default 4) bound its
  memory: about 1 MiB per seat in the worst case, which it prints as it
  starts. `--rate-mbit` limits each room per direction (default 60, 0 = none).
  `--open` admits every room instead of an allow list, for tests only.

## Why it is fast

Every stage is the shortest path the platform offers, and nothing waits in a
queue.

| Stage | How | Cost |
| --- | --- | --- |
| Capture | DXGI Desktop Duplication: the compositor hands over its own GPU texture the moment a frame is presented. Event-driven, no polling. | ~0 |
| Colour conversion | BGRA→NV12 on the GPU's fixed-function video processor. The frame never leaves VRAM. | < 1 ms |
| Encode | The GPU vendor's hardware encoder (NVENC / AMF / Quick Sync) through Media Foundation, fed D3D11 textures directly. Low-latency mode, CBR, no B-frames, no lookahead, infinite GOP. A dedicated thread ships each frame the instant it is produced. | 2–6 ms |
| Transport | One UDP flow, no head-of-line blocking. Frames are split into MTU-sized datagrams, sealed (about a microsecond each) and sent immediately. Lost datagrams are re-requested at once; if that fails a keyframe is requested. No jitter buffer: the bitrate follows the path instead. | network |
| Decode | VideoToolbox hardware decoder, called synchronously on the receive thread. | 2–5 ms |
| Present | The decoded IOSurface is sampled by a Metal shader with no copies and presented with display sync off: no swap-chain queue. | < 1 vsync |
| Pointer | The Mac draws its own cursor (using the host's cursor image), so pointer motion has zero added latency. | 0 |
| Input | Sent the moment the event arrives; every datagram repeats unacknowledged events, so a lost packet never costs a retransmit timeout. Injected with `SendInput`. | network |

The title bar shows the measured capture→presented latency (host and client
clocks are synchronised over the same connection), frame rate, bitrate and
round-trip time.

When nothing on screen changes, nothing is sent. The pipeline only runs while
a client is connected.

## Limitations

- No audio, clipboard sync, file transfer or multi-monitor switching
  (`--display N` picks which monitor to stream).
- Outside access needs one of: UPnP on the router, a manually forwarded
  port, IPv6 at both ends, or a relay. Without a relay, a host behind
  carrier-grade NAT without IPv6 cannot be reached.
- Through a relay, each room is limited to 60 Mbit/s in each direction by
  default, and the longer path over TCP adds delay.
- If the relay stops answering during a relayed session, the client
  reconnects on its own, directly and through the relay. After 3 failed
  attempts in a row it stops with an error that lists each address it tried
  and what the relay answered. Run `hyperspace-client` again once the relay
  is back.
- A pairing made before 0.3.0 has no relay in it: run the client once with
  `--relay URL`, or pair again.
- Two hosts with the same pairing key replace each other on the relay, and
  the host log says so. Run one host per key.
- An explicit HTTP proxy is not supported: the relay connection goes
  straight out over TLS, on port 443 for a `wss://` URL.
- One paired key per host; anyone holding the pairing string has full
  control of the PC.
- UAC prompts and the lock/login screen run on Windows' secure desktop, which
  a normal process can neither capture nor control: the stream pauses until
  it is dismissed locally. Run the host from an elevated prompt if you need to
  control elevated applications.
- Absolute pointer only: games that capture the mouse for camera control will
  not work properly yet.
- Video is 4:2:0 8-bit SDR.
- The cursor image is resampled to match the video scale, so it can look
  slightly soft on Retina displays.
- Host and client must be the same version.

## Building

```bash
cargo build --release            # host on Windows, client on macOS
cargo test --workspace           # protocol, loss recovery, colour conversion
bash scripts/e2e.sh              # real binaries: pairing, wrong key, port forwarding, packet loss
```

The host and a headless client build on every platform: `hyperspace-host
--file stream.h264` replays an encoded stream instead of capturing a desktop,
which lets the whole transport be tested without Windows or a GPU.

```
crates/proto    wire format, encryption, pairing, address lookup, loss recovery, rate control
crates/host     session server, router port mapping; Windows capture → convert → encode → inject
crates/client   session loop; macOS window, VideoToolbox, Metal, input capture
crates/bridge   the host's and the client's link to a relay
crates/relay    the relay server (hyperspace-relay)
```

Releases are built and published by GitHub Actions: bump `version` in the
root `Cargo.toml` and push the default branch (or push a `v*` tag).
