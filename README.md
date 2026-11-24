# hyperspace

A remote desktop built for one thing: the lowest possible latency between a
Windows machine and the Mac you are sitting at. No accounts, no relay servers,
no feature sprawl — a host, a client and one UDP flow between them.

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
once whether to allow it through the firewall: allow it on private networks.
Find the machine's address with `ipconfig`.

**On the Mac**, download and unpack from a terminal (this avoids the
Gatekeeper quarantine a browser download would get):

```bash
curl -L https://github.com/kream0/hyperspace/releases/latest/download/hyperspace-client-macos-universal.tar.gz | tar -xz
```

```bash
./hyperspace-client 192.168.1.50
```

If you downloaded it with a browser instead, clear the quarantine flag first:

```bash
xattr -d com.apple.quarantine hyperspace-client
```

The first connection makes macOS ask whether your terminal may access devices
on the local network: allow it.

Closing the window (or `Ctrl+Option+Cmd+Q`) disconnects cleanly: the host
stops capturing, releases any keys still held, and waits for the next
connection.

> **There is no authentication.** Anyone who can reach UDP port 45800 on the
> host can see and control the desktop. Use it on a network you trust (home
> LAN, or a private overlay such as Tailscale/WireGuard) and never forward the
> port to the internet.

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
hyperspace-client <HOST[:PORT]> [--fps N] [--bitrate MBIT] [--codec h264|hevc]
                  [--fullscreen] [--cmd-as-ctrl] [--stats] [--packet-size N]

hyperspace-host [--port N] [--display N] [--codec h264|hevc] [--encoder auto|hw|sw]
                [--bitrate MBIT] [--max-fps N] [--packet-size N] [--view-only]
                [--list] [--self-test]
```

- The client asks for its display's refresh rate (120 fps on a ProMotion
  panel); the host caps it at its own monitor's refresh rate.
- The default bitrate scales with resolution (about 31 Mbit/s for 1440p60,
  70 Mbit/s for 4K60). On Wi-Fi, try `--bitrate 15` if you see stutter.
- Over a VPN with a small MTU use `--packet-size 1200` on either side.
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
| Transport | One UDP flow, no head-of-line blocking. Frames are split into MTU-sized datagrams and sent immediately. Lost datagrams are re-requested at once (a few ms on a LAN); if that fails a keyframe is requested. No jitter buffer. | network |
| Decode | VideoToolbox hardware decoder, called synchronously on the receive thread. | 2–5 ms |
| Present | The decoded IOSurface is sampled by a Metal shader with no copies and presented with display sync off: no swap-chain queue. | < 1 vsync |
| Pointer | The Mac draws its own cursor (using the host's cursor image), so pointer motion has zero added latency. | 0 |
| Input | Sent the moment the event arrives; every datagram repeats unacknowledged events, so a lost packet never costs a retransmit timeout. Injected with `SendInput`. | network |

The title bar shows the measured capture→presented latency (host and client
clocks are synchronised over the same connection), frame rate, bitrate and
round-trip time.

When nothing on screen changes, nothing is sent. The pipeline only runs while
a client is connected.

## Limitations (MVP)

- No audio, clipboard sync, file transfer or multi-monitor switching
  (`--display N` picks which monitor to stream).
- No authentication or encryption — see the warning above.
- UAC prompts and the lock/login screen run on Windows' secure desktop, which
  a normal process can neither capture nor control: the stream pauses until
  it is dismissed locally. Run the host from an elevated prompt if you need to
  control elevated applications.
- Absolute pointer only: games that capture the mouse for camera control will
  not work properly yet.
- Video is 4:2:0 8-bit SDR.
- The cursor image is resampled to match the video scale, so it can look
  slightly soft on Retina displays.

## Building

```bash
cargo build --release            # host on Windows, client on macOS
cargo test --workspace           # protocol, loss recovery, colour conversion
bash scripts/e2e.sh              # real binaries over loopback, with packet loss
```

The host and a headless client build on every platform: `hyperspace-host
--file stream.h264` replays an encoded stream instead of capturing a desktop,
which lets the whole transport be tested without Windows or a GPU.

```
crates/proto    wire format, fragmentation, NACK/keyframe recovery, input, cursor
crates/host     session server; Windows capture → convert → encode → inject
crates/client   session loop; macOS window, VideoToolbox, Metal, input capture
```

Releases are built and published by GitHub Actions: bump `version` in the
root `Cargo.toml` and push the default branch (or push a `v*` tag).
