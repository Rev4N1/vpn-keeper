# How vpn-keeper works

One `.exe`, C# 5 on .NET Framework 4.8, so it builds with the compiler that
ships with Windows and runs with no install. It has no admin rights and runs
in the user's own desktop session, because that is the only place it can read
and drive Connect Tunnel's windows.

## Processes

```
logon ─▶ vpn-keeper start   (supervisor: restarts the agent if it ever exits)
            └─▶ vpn-keeper agent   (keep awake + proxy + VPN watchdog)
```

`setup` puts a shortcut to `vpn-keeper start` in the Startup folder. The
supervisor and the agent each hold a named mutex, so there is never more than
one of each per session, and an agent crash costs about ten seconds.

## Driving Connect Tunnel

Modern Connect Tunnel has no command line for logging in, so the agent reads
and operates its windows with plain Win32 messages: no mouse, no keyboard
focus, so a locked screen is fine. WinForms control ids change on every start,
so controls are found by class and caption instead. The windows:

| Window | What the agent uses |
|---|---|
| main | combo box (the configuration); a status label (`Disconnected` / `Connecting…` / `Connected`); one button, captioned `Connect` / `Cancel` / `Disconnect` |
| login prompt | a user box (usually prefilled), a password box, `OK` |
| One Time Password Required | one box, `OK` |

Details that matter in practice:

- **`&` shortcut markers.** A button's text is often `&Connect` (the `&`
  underlines the Alt key). Captions are compared with the marker stripped.
- **The tray.** Once connected, Connect Tunnel hides its main window. Hidden
  WinForms windows are read too, so the status is never lost; login prompts are
  only acted on while actually on screen.
- **Filling and clicking.** Text goes in with `WM_SETTEXT` (password boxes
  accept it; they only refuse to be read). `OK` is a *posted* `BM_CLICK`,
  because it opens the next modal dialog. If a dialog ignores it, the agent
  falls back to a mouse click, then Enter.
- **Notices.** Any window with `OK` and no boxes (e.g. the server's "session has
  been idle ... disconnected") is closed on sight: while it is open, `Connect`
  stays enabled but is ignored. A Connect that changes nothing is retried in
  30 s without the login backoff, since nothing was sent.
- **Refused or expired password.** A second password prompt in one login, a
  notice saying the password is wrong or expired, or a required change with
  nothing queued makes the agent hold: no more logins until the saved
  password changes or a new one is queued.
- **New password.** `/password` (a current one-time code, each code once, 5
  wrong codes lock it for 15 min) queues one in Credential Manager entry
  `vpn-keeper:change` (empty = none). It is used: in a change prompt (3+
  boxes or "new password" text; boxes found by label old/current, new,
  confirm/again, else by order), becoming the saved one once the VPN is up;
  or, once, when the saved one is refused. A change offer (Yes/No, text about
  the password changing or expiring) is answered Yes only with one queued. A
  change prompt shown again for the same password drops it. Force is the
  entry's user name `force` (so `vpn-keeper password` in another process can
  set it): the agent clears it and disconnects, so the next login is now,
  and in that login ticks the prompt's "change password" check box (a button
  whose caption has change/cambiar and password/contraseña). Its state is read
  with `BM_GETCHECK`, except on owner-drawn boxes, which start clear. Other
  logins leave it clear.
- **Dumps.** The login prompt is dumped too, once per agent run.
- **Dumps.** Each distinct notice, change prompt, or window blocking Connect
  is written to `dumps\` beside the log: captions, classes and states, never
  box contents.
- **Clicking a hidden window.** In the tray, Connect Tunnel's window is
  hidden and its buttons ignore `BM_CLICK`, so the click goes to the parent as
  `WM_COMMAND`/`BN_CLICKED`, which WinForms turns into `Click`.
- **Updating.** A running `.exe` can be renamed but not overwritten:
  `update` moves it to `.old` and copies the new one in. The agent sees its
  file change and exits; the supervisor sees it too and starts a new
  supervisor from the new file, in the same desktop session. Sleep stays
  blocked throughout: the supervisor blocks it as well as the agent, the old
  supervisor lingers 15 s after starting the new one, and `update` itself
  blocks it for 90 s (for older supervisors, which left a gap; a long-idle PC
  sleeps the moment nothing blocks it).
- **Language.** English and Spanish captions are both recognised.

`vpn-keeper status` prints what the agent currently sees, for when a Connect
Tunnel update changes something.

## The watchdog loop

Every 30 s while connected, every few seconds otherwise:

- a **login prompt open** (the server asking again) → answer it;
- **Disconnected** → check the selected configuration matches, press Connect,
  enter the password and the code, wait for `Connected`;
- **Connected** → request the check URL. Three failures in a row means a dead
  tunnel: disconnect, so the next pass logs in fresh. (The requests do not
  hold off the server's idle timeout; the next pass simply logs in again.)
- **Connecting/Reconnecting** with no prompt for 3 minutes → Cancel;
- **not running** → start Connect Tunnel.

Safeguards:

- **Lockout-safe.** A refused password is never typed again (see above).
  Other failed logins back off 2, then 5, then 15 minutes.
- **Never stuck.** A watchdog pass takes 2 minutes at most; if none completes
  in 10, the agent exits and the supervisor starts a fresh one. Proxy sockets
  use TCP keep-alive, so connections whose peer vanished are dropped.
- **Codes used once.** A one-time code is never reused, and one about to expire
  is held until the next 30-second window.
- **Secrets** are read from Credential Manager (DPAPI, this user only) at each
  login and never written to the log.

## Keeping awake

While vpn-keeper runs, the agent and the supervisor both hold
`ES_SYSTEM_REQUIRED`, like a video player: idle sleep is blocked, nothing is
reconfigured, and it is released when they stop. The screen can still turn off and lock. The lid is a separate Windows
setting.

## The proxy

A small HTTP proxy (`CONNECT` for https, absolute URLs for http). Names are
resolved on this PC, so internal names and the VPN's DNS work, and traffic
follows the VPN's split-tunnel routes. Two lists keep it from being an open
door: `clients` (who may connect) and `allow` (where it may go); anything else
gets 403. `/proxy.pac` is generated from `allow` and points at the address the
request arrived on, so browsers send exactly the shared sites to the proxy and
everything else direct. The listener restarts itself if it ever fails.

## The firewall rule

The one thing a plain proxy needs that admin rights gate is an inbound
firewall rule for its port, scoped to the client subnets. `setup` creates it
(and `uninstall` removes it) through a single UAC prompt; because the admin
who answers that prompt may be a different account from the signed-in user,
the rule's values are passed to the elevated step on the command line rather
than re-read from the user's config.

(If a client whose subnet the VPN has also claimed — e.g. a `10.x` home-VPN
subnet under a company `10.0.0.0/8` route — still can't reach the proxy after
the firewall rule, add a route for that subnet via the LAN gateway:
`route -p add <net> mask <mask> <gateway> metric 1`. In practice the home
router's return path usually makes this unnecessary.)

## Tests

`build.ps1 -Test` builds a separate `tests.exe` (no test code ships in
`vpn-keeper.exe`) and runs it. It covers TOTP against the RFC 6238 vectors,
Base32, the status captions, the allow lists and PAC, request parsing, the
config round-trip, and the proxy over real sockets. Given a fake
`SnwlConnect.exe` — a WinForms program with the same windows, `&` markers and
tray-hiding, that actually checks the password and code — it also runs a full
login and a forced re-login end to end. CI runs all of it on every push.
