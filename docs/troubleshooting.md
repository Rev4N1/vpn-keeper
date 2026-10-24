# Troubleshooting

Start with the log, `%LOCALAPPDATA%\vpn-keeper\vpn-keeper.log` on the laptop,
and `http://<laptop>:8080/health`.

## From the other machine, the page does not load

Work through the path in order:

1. **WireGuard up?** Its app shows a recent handshake.
2. **Proxy reachable?** Open `http://<laptop>:8080/health`.
   - Times out: the router rule to `<laptop>:8080`, the client's
     `AllowedIPs`, the laptop's firewall rule, or the route for the
     WireGuard subnet (see setup, step 2: without it, replies may go into
     the company tunnel).
   - `403 ... not in the proxy's 'clients' list`: add your WireGuard subnet to `clients`.
3. **Health says `vpn: Up`?** If not, see below.
4. **PAC in use?** `http://<laptop>:8080/proxy.pac` must load, and the browser
   must use it (Windows caches PAC files; turning *Use setup script* off and
   on refreshes it).
5. **`403 ... not in the proxy's 'allow' list`**: add the site to `allow` in
   `vpn-keeper.conf` and restart the agent.
6. **`502 ... unreachable`**: the VPN is down, or that host is not routed by it.

## The VPN does not log in

| Log line | Meaning |
|---|---|
| `set 'profile' in ...` | fill in `vpn-keeper.conf` |
| `no saved VPN password` / `no saved OTP seed` | run the `cmdkey` commands from the setup, as the same Windows user |
| `the OTP seed is not Base32` | the seed is the A-Z/2-7 text, not the 6-digit code or the QR URL |
| `Connect Tunnel has profile '...' selected` | pick the right configuration in Connect Tunnel once |
| `the password dialog did not accept the password` | wrong password (it waits 2, 5, then 60 min: fix it before the account locks) |
| `the one-time code dialog did not accept the code` | compare `vpn-keeper.exe otp` with your app; check the laptop's clock |
| `Connect Tunnel went back to Disconnected` | the server refused; the `Connect Tunnel says: ...` lines before it give its message |
| `Connect Tunnel is running without its window` | it is in the tray; the agent reopens it |
| `no enabled Connect button yet; buttons seen: ...` | the main button's caption is not one the agent knows: run `vpn-keeper.exe dump` and compare |

`vpn-keeper.exe login` runs one login in the foreground with the log on
screen; end the background agent first (Task Manager) so they don't both act.

## The laptop sleeps anyway

The agent blocks *idle* sleep only. The lid, the power button, or a policy
forcing hibernation still apply. `powercfg /requests` lists `vpn-keeper.exe`
under SYSTEM while it runs.

## SSH to a domain-joined laptop resets right after login

A key-based login has no password, so Windows asks a domain controller, which
may only be reachable through the VPN. With the VPN down, the session resets
after the key is accepted; it works again once the VPN is back.

## Connect Tunnel changed after an update

If an update renames windows or buttons, logins time out. `vpn-keeper.exe dump`
shows the windows exactly as the agent sees them (which one it takes for the
main window, the status, the main button, the prompts). Two read-only
scripts in `tools/` give more: `uia-dump.ps1` (run it once per window:
main, login prompt, code prompt) writes the controls to
`%USERPROFILE%\uia-dump.txt`; `laptop-probe.ps1 -Targets host:port,...`
collects versions, routes, DNS and power settings to `vpn-probe.txt` on the
Desktop.
