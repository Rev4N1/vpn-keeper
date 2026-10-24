# vpn-keeper

Keeps a SonicWall Connect Tunnel VPN logged in on a Windows PC, and shares it
with your other machines through a small proxy. Set it up once; after that it
runs on its own and you never think about it.

Useful when a company VPN only runs on one machine, but you need its internal
services from elsewhere, for example over a home VPN into that machine.

```
 other PC ──▶ this PC :8080 ──Connect Tunnel VPN──▶ company network
 (browser)    vpn-keeper                            internal sites
```

What it does, unattended:

- **Logs the VPN back in by itself** whenever it drops: presses Connect, types
  the password, and types the current 6-digit code. It works with the screen
  locked, and recovers from the session timeouts that SonicWall servers apply.
- **Keeps the PC awake**, so idle sleep never cuts the VPN.
- **Shares the VPN** through an HTTP proxy, so a browser on another machine
  reaches the internal sites and nothing else.
- **Restarts itself** if the agent or the proxy ever fails, and starts at every
  logon.

The VPN password and the one-time-code seed are kept in Windows Credential
Manager. They are never in a file, the log, or this repository.

> Automating a second factor weakens it. Use this only where your organisation
> allows it.

## Set up (on the PC with the VPN)

1. Download `vpn-keeper.exe` from [Releases](../../releases).
2. In Connect Tunnel, pick your configuration once (so its name is selected).
3. In PowerShell:

   ```powershell
   .\vpn-keeper.exe setup
   ```

   It asks for the configuration name, a URL that only answers through the VPN,
   the sites to share, and your VPN password and one-time-code seed (the Base32
   text from "can't scan the QR code?"). It then installs itself, starts, and
   prints two commands to run once **as administrator**: a firewall rule for
   the proxy port, and, if needed, a route so replies to your other machines
   don't disappear into the VPN.

That's it. Check it any time with `vpn-keeper status`.

## Use it from another machine

Set the browser's **automatic proxy configuration (PAC)** URL to the one
`setup` prints, e.g. `http://192.168.1.50:8080/proxy.pac`:

- Windows (Edge/Chrome): Settings → Network & internet → Proxy → *Use setup
  script* → On. No admin needed.
- Firefox: Settings → Network Settings → *Automatic proxy configuration URL*.

Only the shared sites go through the proxy; everything else stays direct.
`http://<pc>:8080/health` shows the VPN state and the last login.

To reach it from outside the home network, bring that network within reach
(e.g. a home VPN) and make sure the PC's firewall rule allows your client's
addresses.

## Commands

| Command | Does |
|---|---|
| `vpn-keeper setup` | set up, or change settings (Enter keeps each current value) |
| `vpn-keeper status` | what's set, what's running, and what to fix |
| `vpn-keeper uninstall` | stop it, remove autostart, delete the saved secrets |
| `vpn-keeper run` | run in the window with the log on screen (for testing) |

Settings live in `vpn-keeper.conf` next to the installed `.exe`; the log is in
`%LOCALAPPDATA%\vpn-keeper\vpn-keeper.log`.

## Build

Every push runs [CI](.github/workflows/build.yml) on Windows: it compiles and
runs the tests, including a full login against a fake Connect Tunnel shaped
like the real one. Tags like `v1.0.0` make a release, `v1.0.0-beta.1` a
pre-release.

Building needs only Windows (the C# compiler in .NET Framework 4.8, no SDK):

```powershell
.\build.ps1          # -> dist\vpn-keeper.exe
.\build.ps1 -Test    # also run the tests (a fake window flashes briefly)
```

How it works inside: [docs/design.md](docs/design.md).
