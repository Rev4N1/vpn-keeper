# Setup

Example values used below; use yours:

| | example |
|---|---|
| laptop | `192.168.1.50` (give it a fixed address: a static DHCP lease on the router) |
| home router | `192.168.1.1`, LAN `192.168.1.0/24` |
| WireGuard subnet | `10.7.0.0/24` |
| internal service | `http://10.20.30.40/`, `*.corp.example` |

## 1. Laptop, as yourself

1. Download `vpn-keeper.exe` from **Releases** (`latest`, or a `v*` release)
   into a folder of its own, e.g. `%LOCALAPPDATA%\Programs\vpn-keeper\`.
2. Next to it, create `vpn-keeper.conf` from
   [vpn-keeper.conf.example](../vpn-keeper.conf.example) and set:
   - `profile`: the *Configuration* name shown in Connect Tunnel. The agent
     refuses to log in to any other.
   - `check_url`: something that only answers through the VPN.
   - `allow`: the networks and domains behind the VPN you want to reach.
3. Save the two secrets in Windows Credential Manager. `/pass` with nothing
   after it makes `cmdkey` ask, so nothing lands in your shell history:

   ```powershell
   cmdkey /generic:vpn-keeper:vpn /user:<vpn user> /pass
   cmdkey /generic:vpn-keeper:otp /user:otp /pass
   ```

   For the second, paste the TOTP **seed**: the Base32 text (A-Z and 2-7)
   offered as "can't scan the QR code?" when the authenticator was set up.
   Spaces are fine. Run the same command again to change it; Control Panel →
   Credential Manager → Windows Credentials lists them.
4. Check:

   ```powershell
   .\vpn-keeper.exe check
   .\vpn-keeper.exe otp
   ```

   `otp` must match your authenticator app. If it does not, the seed is wrong
   and logins would fail.
5. Real test: disconnect the VPN in Connect Tunnel, then

   ```powershell
   .\vpn-keeper.exe login
   ```

   It should press Connect, enter the password and the code, and end with
   `VPN connected`.
6. Install, so it starts now and at every logon:

   ```powershell
   .\vpn-keeper.exe install
   ```

It runs while you are logged in to Windows (locked is fine, signed out is
not). It blocks idle sleep, but the lid follows Windows' lid setting: set
*When I close the lid* to *Do nothing* on mains power, or keep it open.

## 2. Laptop, as an administrator (once)

Open PowerShell **as administrator**:

```powershell
# Let the LAN and WireGuard clients reach the proxy.
New-NetFirewallRule -DisplayName "vpn-keeper proxy" -Direction Inbound -Protocol TCP -LocalPort 8080 `
  -RemoteAddress 10.7.0.0/24,192.168.1.0/24 -Action Allow -Profile Any
```

Then check whether the company VPN claims your WireGuard subnet. Many push
broad routes such as `10.0.0.0/8`; if one covers the WireGuard subnet, the
laptop sends its replies to WireGuard clients into the company tunnel and
they never arrive. With the VPN connected:

```powershell
Find-NetRoute -RemoteIPAddress 10.7.0.2 | Select-Object -Last 1 InterfaceAlias, NextHop
```

If the interface is the VPN's, add a more specific route via the home router:

```powershell
route -p add 10.7.0.0 mask 255.255.255.0 192.168.1.1 metric 1
```

(Or move WireGuard to a subnet the company VPN does not use.)

## 3. Home router

- Fixed address for the laptop (static DHCP lease).
- Allow WireGuard clients to reach `192.168.1.50` on TCP 8080 (on OpenWrt: a
  traffic rule from the WireGuard zone to `lan`, destination
  `192.168.1.50`, port 8080).
- WireGuard clients that only route some LAN hosts need `192.168.1.50/32` in
  their `AllowedIPs`.

## 4. The other machine

1. Connect WireGuard.
2. PAC URL `http://192.168.1.50:8080/proxy.pac` in the browser (see the README).
3. Open `http://192.168.1.50:8080/health`, then the internal sites.

## Updating

End the running agent (Task Manager → vpn-keeper.exe → End task), replace the
.exe, then `.\vpn-keeper.exe install` (re-creates the shortcut and starts it).
