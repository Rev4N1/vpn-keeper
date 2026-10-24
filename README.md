# vpn-keeper

Keeps a SonicWall Connect Tunnel VPN logged in on a Windows laptop at home,
and shares it with your other machines through a small proxy. Useful when
the company VPN only runs on one machine but you need its internal services
from somewhere else (for example, over a WireGuard VPN into your home).

```
 other PC ──WireGuard──▶ home router ──▶ laptop :8080 ──SonicWall VPN──▶ company network
 (browser + PAC)                         vpn-keeper.exe                   internal services
```

`vpn-keeper.exe` runs on the laptop, in your Windows session, and does three things:

1. **Logs the VPN in by itself.** It watches Connect Tunnel, and whenever the
   VPN is down (or the server ends the session and asks again, as SMA servers
   do every few hours), it presses Connect, types the password and the
   one-time (TOTP) code, and checks that traffic flows again. No mouse or
   keyboard is used, so it works with the screen locked.
2. **Keeps the laptop awake.** Idle sleep would cut the network and the VPN.
3. **Shares the VPN with an HTTP proxy** (port 8080) and a PAC file, so a
   browser elsewhere sends only the internal addresses through it.

The VPN password and the TOTP seed stay in Windows Credential Manager on the
laptop. They are never in the config file or the log.

> Automating a second factor weakens it. Use this only where your
> organisation allows it.

## Using it from another machine

1. Reach the laptop's network (e.g. WireGuard into your home LAN).
2. Set the browser's automatic proxy configuration (PAC) URL to
   `http://<laptop>:8080/proxy.pac`:
   - Windows (Edge, Chrome): Settings → Network & internet → Proxy →
     *Use setup script* → On. No admin needed.
   - Firefox: Settings → Network Settings → *Automatic proxy configuration URL*.
3. Open the internal sites as usual; everything else stays direct.

`http://<laptop>:8080/health` shows the VPN state, the last login and the
last error.

## Ports

| Where | What |
|---|---|
| Internet → home | nothing new (only what your WireGuard already uses) |
| Home router | let WireGuard clients reach `<laptop>:tcp:8080` |
| Laptop (Windows Firewall) | inbound TCP 8080 from your WireGuard subnet and LAN (admin, once) |
| Laptop (routing) | a route for your WireGuard subnet via the home router, **if** the company VPN's routes cover it (admin, once) |

Details and exact commands: [docs/setup.md](docs/setup.md).

## Quick start (on the laptop)

```powershell
copy vpn-keeper.conf.example vpn-keeper.conf   # then set profile, check_url, allow
cmdkey /generic:vpn-keeper:vpn /user:<vpn user> /pass   # asks for the VPN password
cmdkey /generic:vpn-keeper:otp /user:otp /pass          # paste the Base32 TOTP seed
.\vpn-keeper.exe check      # everything found?
.\vpn-keeper.exe otp        # same code as your authenticator app?
.\vpn-keeper.exe login      # with the VPN disconnected: the real test
.\vpn-keeper.exe install    # start now and at every logon
```

## Commands

| Command | Does |
|---|---|
| `vpn-keeper.exe` | run the agent (in a terminal it shows the log live; Ctrl+C stops it) |
| `check` | config, saved credentials, Connect Tunnel state |
| `otp` | the current one-time code, to compare with your authenticator app |
| `login` | log the VPN in once and exit |
| `dump` | the Connect Tunnel windows as the agent sees them (for diagnosing) |
| `install` / `uninstall` | start at every logon (a shortcut in your Startup folder) / stop that |
| `selftest` | built-in tests |
| `version` | the build version |

Settings: `vpn-keeper.conf` next to the .exe; see
[vpn-keeper.conf.example](vpn-keeper.conf.example). It is git-ignored.
Log: `%LOCALAPPDATA%\vpn-keeper\vpn-keeper.log`.

## Builds

Every push runs [CI](.github/workflows/build.yml) on Windows: it compiles,
runs the self-test (including a full login, and a forced re-login, against a
fake Connect Tunnel shaped like the real one), and keeps the result as a
build artifact. Pushes to `main` also update the **latest** pre-release;
tagging `v1.2.3` makes a release, and `v1.2.3-beta.1` a pre-release.

Building locally needs only Windows (the C# compiler that ships with .NET
Framework 4.8):

```powershell
.\build.ps1          # -> dist\vpn-keeper.exe
.\build.ps1 -Test    # plus the self-test; a fake Connect Tunnel window opens briefly
```

More: [how it works](docs/how-it-works.md) · [troubleshooting](docs/troubleshooting.md)
