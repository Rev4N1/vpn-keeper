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
   **offers to apply the one admin step for you** through a single Windows
   admin prompt: the firewall rule that lets your other machines reach the
   proxy port. (It prints the command too, to run by hand if you prefer.)

That's it. Check it any time with `vpn-keeper status`.

## Use it from another machine

Set the browser's **automatic proxy configuration (PAC)** URL to the one
`setup` prints, e.g. `http://192.168.1.50:8080/proxy.pac`:

- Windows (Edge/Chrome): Settings → Network & internet → Proxy → *Use setup
  script* → On. No admin needed.
- Firefox: Settings → Network Settings → *Automatic proxy configuration URL*.

Only the shared sites go through the proxy; everything else stays direct.
`http://<pc>:8080/health` shows the VPN state and the last login.

### When the VPN password expires or changes

Give vpn-keeper the new password on `http://<pc>:8080/password`, from any
machine that may use the proxy (or `vpn-keeper password` on the PC). The page
asks for the current 6-digit code from your authenticator app, so others who
can reach the proxy can't use it; five wrong codes lock it for 15 minutes.

The new password **waits**; the current one stays in use until:

- the VPN asks for a password change while logging in (it offers this when
  the password is about to expire, and requires it once expired): vpn-keeper
  fills in the old and the new password, and once the VPN is up the new one
  is the saved one;
- or the current password is refused (you changed it elsewhere): vpn-keeper
  switches to the new one.

Tick **Force** to reconnect right away, so the VPN gets its chance to ask
now instead of at the next login. While the VPN is asking, the page shows a
banner, and `/health` shows `VPN asking for a new password` and `new password
queued`. With nothing queued, an offer is declined and the login goes on;
a required change stops logins until you queue one.

vpn-keeper never types a refused password twice, so it can't lock your
account. A new password the VPN refuses is dropped, never retyped; queue
another. Every prompt and notice Connect Tunnel shows is written once to
`%LOCALAPPDATA%\vpn-keeper\dumps\` (captions and layout, never box contents),
to check against when the VPN does something new.

To reach it from outside the home network, bring that network within reach
(e.g. a home VPN) and make sure the PC's firewall rule allows your client's
addresses.

## Commands

| Command | Does |
|---|---|
| `vpn-keeper setup` | set up, or change settings (Enter keeps each current value) |
| `vpn-keeper password` | queue a new VPN password (see above) |
| `vpn-keeper update` | run from a newly downloaded `.exe`: installs it over the running one, which restarts on it by itself; settings and secrets stay (works over SSH) |
| `vpn-keeper status` | what's set, what's running, and what to fix |
| `vpn-keeper uninstall` | stop it, remove autostart, delete the saved secrets |
| `vpn-keeper run` | run in the window with the log on screen (for testing) |

Settings live in `vpn-keeper.conf` next to the installed `.exe`; the log is in
`%LOCALAPPDATA%\vpn-keeper\vpn-keeper.log`.

### Connect only during set hours

`setup` asks for this, or set `hours` in `vpn-keeper.conf`:

```
hours = 07:30-17:30                             # same window every day
hours = Mon-Thu 07:45-17:00, Fri 07:45-15:00    # weekdays, shorter Friday, weekend off
```

Each rule is an optional day part (`Mon`, `Mon-Thu`, `Mon,Wed,Fri`) and a
`HH:MM-HH:MM` window; a rule with no days applies every day. Outside every
rule the agent keeps the VPN disconnected and never logs in. Empty = always.
A window whose end is before its start (like `22:00-06:00`) runs overnight.

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
