# hyperspace

A remote desktop built for one thing: the lowest possible latency between a
Windows machine and the Mac you are sitting at - on the same network or from
anywhere else. No accounts, no relay servers, no VPN: the client talks
straight to the host over one encrypted UDP flow.

- **Host**: Windows 10/11 (`hyperspace-host.exe`)
- **Client**: macOS 12+ on Apple Silicon or Intel (`hyperspace-client`)

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
| Provider uses carrier-grade NAT (no public IPv4) | "its own address is not public" | Connect over IPv6 (both ends need it), or ask the provider for a public IPv4 |
| Windows Firewall blocks public networks | (client gets no answer) | Allow hyperspace-host for public networks |
| Network you are on blocks UDP | (client gets no answer) | Use another network / tethering |

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

hyperspace-host [--port N] [--display N] [--codec h264|hevc] [--encoder auto|hw|sw]
                [--bitrate MBIT] [--max-fps N] [--view-only]
                [--public-host NAME] [--no-upnp] [--no-dht] [--new-key]
                [--list] [--self-test]
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
  port, or IPv6 at both ends. There is no relay, so a host behind
  carrier-grade NAT without IPv6 cannot be reached.
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
```

Releases are built and published by GitHub Actions: bump `version` in the
root `Cargo.toml` and push the default branch (or push a `v*` tag).
