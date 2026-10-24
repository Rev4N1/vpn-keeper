using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Text;

namespace VpnKeeper
{
    // The one-time steps that need administrator rights: the inbound firewall
    // rule for the proxy, and a route so replies to proxy clients on a subnet
    // the VPN has claimed go back out the LAN, not into the tunnel.
    //
    // setup offers to do this through a single UAC prompt (it re-launches the
    // 'netsetup' command elevated). The same commands are always printed too,
    // so anyone can do it by hand instead.
    static class Admin
    {
        public const string FirewallRule = "vpn-keeper";

        public static bool IsElevated()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
        }

        // The client subnets that need a route via the LAN gateway: any CIDR
        // that is not the directly-connected LAN, loopback, or the whole
        // internet. (The LAN needs no route; the rest arrive via the router,
        // so their replies must go back to it.)
        public static List<string> RoutesNeeded(List<string> clients, string lanSubnet)
        {
            List<string> routes = new List<string>();
            foreach (string c in clients)
            {
                if (!Rules.IsCidr(c)) continue;
                if (c == lanSubnet || c.StartsWith("127.") || c == "0.0.0.0/0") continue;
                if (!routes.Contains(c)) routes.Add(c);
            }
            return routes;
        }

        // Run elevated as the 'netsetup' command. Returns 0 on success.
        public static int Apply(Config cfg, Lan lan)
        {
            if (!IsElevated()) { Log.Error("netsetup needs administrator rights"); return 1; }
            int bad = 0;

            string remote = string.Join(",", CidrClients(cfg.Clients).ToArray());
            if (remote.Length == 0) remote = "LocalSubnet";
            Run("netsh", "advfirewall firewall delete rule name=\"" + FirewallRule + "\"");   // ignore result
            bad += Run("netsh", "advfirewall firewall add rule name=\"" + FirewallRule + "\" dir=in action=allow protocol=TCP localport="
                + cfg.Port + " remoteip=" + remote) ? 0 : 1;

            if (lan != null)
                foreach (string c in RoutesNeeded(cfg.Clients, lan.Subnet))
                {
                    string net, mask;
                    System.Net.IPAddress host;
                    Rules.ParseCidr(c, out net, out mask, out host);
                    Run("route", "delete " + net);   // so -p add is idempotent
                    bad += Run("route", "-p add " + net + " mask " + mask + " " + lan.Gateway + " metric 1") ? 0 : 1;
                }
            return bad == 0 ? 0 : 1;
        }

        // Launch setup's elevated worker; a UAC prompt appears. Returns:
        // 0 applied, 1 the worker reported a problem, -1 the prompt was declined.
        public static int Elevate()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(Config.InstalledExe, "netsetup") { UseShellExecute = true, Verb = "runas" };
                using (Process p = Process.Start(psi))
                {
                    p.WaitForExit();
                    return p.ExitCode == 0 ? 0 : 1;
                }
            }
            catch (Win32Exception) { return -1; }   // user said No to UAC
        }

        public static List<string> CidrClients(List<string> clients)
        {
            List<string> c = new List<string>();
            foreach (string e in clients) if (Rules.IsCidr(e)) c.Add(e);
            return c;
        }

        static bool Run(string exe, string args)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(exe, args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using (Process p = Process.Start(psi))
                {
                    string outp = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                    p.WaitForExit();
                    Log.Info("admin: " + exe + " " + args + " -> exit " + p.ExitCode);
                    if (outp.Trim().Length > 0) Log.Debug("admin: " + outp.Trim());
                    return p.ExitCode == 0;
                }
            }
            catch (Exception e) { Log.Error("admin: " + exe + " failed: " + e.Message); return false; }
        }
    }
}
