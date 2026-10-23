# How it works

## Why it drives the client's windows

SonicWall SMA servers can require a password plus a TOTP code, and can end
sessions after a fixed time ("VPN disconnected due to credential
expiration"), after which Connect Tunnel cannot reconnect without both again.
Modern Connect Tunnel has no command line for this, so the agent drives its
windows.

## Driving Connect Tunnel

Connect Tunnel's UI is Windows Forms. The windows the agent knows:

| Window | Controls used |
|---|---|
| main | combo box *Configuration*; status label `Disconnected` / `Connecting...` / `Connected`; one button whose caption is `Connect` / `Cancel` / `Disconnect` |
| login prompt (its title and labels come from the server and may be localised) | user box (usually prefilled), password box, `OK` |
| **One Time Password Required** | one box ("Enter 6 digit code…"), `OK` |

Control ids change on every start, so controls are found by class and
caption: the main window is the one with a status label; a dialog with
`OK` and two text boxes is the login prompt (the password box is the one
after a "Password"/"Contraseña" label, else the last); with one box, the
code prompt. English and Spanish captions are recognised.

Text is set with `WM_SETTEXT` and buttons pressed with a posted `BM_CLICK`
(posted, because OK on the login prompt opens the next modal dialog). If a
dialog ignores that, the agent tries a mouse press, then Enter. None of this
needs the window in front or the keyboard, so a locked screen is fine.
Windows can only be driven from the same desktop session, which is why the
agent starts from your Startup folder rather than as a service.

`tools/uia-dump.ps1` prints these windows' controls; run it if a Connect
Tunnel update changes them.

## The loop

Every `check_interval` seconds while connected (5 s while not):

- **A login prompt is open** (re-authentication, or a half-done login):
  answer it.
- **Disconnected:** check the selected profile is `profile`, press Connect,
  answer the prompts, wait for `Connected` (two minutes at most).
- **Connected:** request `check_url`; any HTTP answer counts. After
  `failed_checks` failures in a row the tunnel is considered dead: press
  Disconnect, and the next pass logs in again.
- **Connect Tunnel not running, or no window:** start it.

Safety:

- **Lockouts.** Corporate VPN passwords are often directory accounts that
  lock, so a failed login waits 2 min, then 5, then 60 between tries. A
  missing credential or a wrong profile waits 5 min and logs why.
- **Codes are never reused.** A code is used once; the next login waits for
  the next 30 s window, and a code with under 4 s left is not sent.
- **Secrets.** They are read from Credential Manager (DPAPI, this Windows user
  only) at each login and never logged.

## Keeping the laptop awake

While the agent runs it holds `ES_SYSTEM_REQUIRED`
(`SetThreadExecutionState`), as a video player does: no admin, no setting
changed, released when the agent stops. The display can still turn off and
lock. The lid is a separate setting.

## The proxy

A plain HTTP proxy (`CONNECT` for https, absolute URLs for http) on
`listen`. Names are resolved on the laptop, so internal names and the VPN's
DNS work, and traffic follows the VPN's split-tunnel routes. Two lists keep
it from being an open door:

- `clients`: who may use it (on top of the firewall rule).
- `allow`: where it may go; anything else gets 403.

`/proxy.pac` is generated from `allow` and points at the address the
request came in on, so browsers send exactly those destinations to the proxy
and everything else direct. It never makes the client resolve names
(`isInNet` only runs on literal IPs). `/health` reports the state.

## Tests

`selftest` covers TOTP (the RFC 6238 vectors), Base32, status captions, the
allow lists and PAC, request parsing, the config file, and the proxy over
real sockets (http, CONNECT, refusals, PAC, health). Given
`tests/FakeSnwlConnect.cs`, a Windows Forms stand-in with the same window
structure that checks the password and the code for real, it also runs a
full login and a forced re-login end to end. CI runs all of it on every push.
