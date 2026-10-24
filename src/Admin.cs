using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Security.Principal;

namespace VpnKeeper
{
    // The one-time steps that need administrator rights: the inbound firewall
    // rule for the proxy, and a route so replies to proxy clients on a subnet
    // the VPN has claimed go back out the LAN, not into the tunnel.
    //
    // setup computes exactly what to do (Plan), then re-launches 'netsetup'
    // elevated with those values ON THE COMMAND LINE. It must not re-read the
    // config when elevated: the admin that answers the UAC prompt may be a
    // different account whose profile has no settings. The same commands are
    // printed too, so anyone can run them by hand instead.
    class AdminPlan
    {
        public int Port;
        public string RemoteIp;              // CIDRs, comma-separated, or "LocalSubnet"
        public List<string[]> Routes = new List<string[]>();   // each {network, mask, gateway}

        // "port=8080 remoteip=10.7.0.0/24,192.168.1.0/24 route=10.7.0.0,255.255.255.0,192.168.1.1"
        public string ToArgs()
        {
            string s = "port=" + Port + " remoteip=" + RemoteIp;
            foreach (string[] r in Routes) s += " route=" + r[0] + "," + r[1] + "," + r[2];
            return s;
        }
    }

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

        public static List<string> CidrClients(List<string> clients)
        {
            List<string> c = new List<string>();
            foreach (string e in clients) if (Rules.IsCidr(e)) c.Add(e);
            return c;
        }

        // What the admin step will do, computed in the user's own context.
        public static AdminPlan Plan(Config cfg, Lan lan)
        {
            AdminPlan p = new AdminPlan();
            p.Port = cfg.Port;
            List<string> cidrs = CidrClients(cfg.Clients);
            p.RemoteIp = cidrs.Count > 0 ? string.Join(",", cidrs.ToArray()) : (lan != null ? lan.Subnet : "LocalSubnet");
            if (lan != null)
                foreach (string c in RoutesNeeded(cfg.Clients, lan.Subnet))
                {
                    string net, mask;
                    IPAddress host;
                    Rules.ParseCidr(c, out net, out mask, out host);
                    p.Routes.Add(new[] { net, mask, lan.Gateway });
                }
            return p;
        }

        // Launch the elevated worker with the plan on its command line; a UAC
        // prompt appears. 0 applied, 1 the worker reported a problem, -1 declined.
        public static int Elevate(AdminPlan plan)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(Config.InstalledExe, "netsetup " + plan.ToArgs()) { UseShellExecute = true, Verb = "runas" };
                using (Process p = Process.Start(psi))
                {
                    p.WaitForExit();
                    return p.ExitCode == 0 ? 0 : 1;
                }
            }
            catch (Win32Exception) { return -1; }   // user said No to UAC
        }

        // The elevated worker: parse the plan from args and apply it. Reads no
        // config, so it does not matter which account UAC elevated to.
        public static int ApplyFromArgs(string[] args)
        {
            if (!IsElevated()) { Log.Error("netsetup needs administrator rights"); return 1; }
            int port = 0;
            string remote = "LocalSubnet";
            List<string[]> routes = new List<string[]>();
            foreach (string a in args)
            {
                if (a.StartsWith("port=")) int.TryParse(a.Substring(5), out port);
                else if (a.StartsWith("remoteip=")) remote = a.Substring(9);
                else if (a.StartsWith("route="))
                {
                    string[] r = a.Substring(6).Split(',');
                    if (r.Length == 3) routes.Add(r);
                }
            }
            if (port < 1 || port > 65535) { Log.Error("netsetup: bad port"); return 1; }

            int bad = 0;
            Run("netsh", "advfirewall firewall delete rule name=\"" + FirewallRule + "\"");   // ignore result
            bad += Run("netsh", "advfirewall firewall add rule name=\"" + FirewallRule + "\" dir=in action=allow protocol=TCP localport="
                + port + " remoteip=" + remote) ? 0 : 1;
            foreach (string[] r in routes)
            {
                Run("route", "delete " + r[0]);   // so -p add is idempotent
                bad += Run("route", "-p add " + r[0] + " mask " + r[1] + " " + r[2] + " metric 1") ? 0 : 1;
            }
            return bad == 0 ? 0 : 1;
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
