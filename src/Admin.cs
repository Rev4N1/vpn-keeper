using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace VpnKeeper
{
    // The one admin step: an inbound firewall rule that lets the proxy clients
    // reach the proxy port. setup computes it in the user's own context, then
    // re-launches 'netsetup' elevated with the values ON THE COMMAND LINE. It
    // must not re-read the config when elevated: the admin that answers the UAC
    // prompt may be a different account whose profile has no config. The command
    // is printed too, so it can be run by hand instead.
    class AdminPlan
    {
        public int Port;
        public string RemoteIp;   // CIDRs, comma-separated, or "LocalSubnet"

        public string ToArgs() { return "port=" + Port + " remoteip=" + RemoteIp; }
    }

    static class Admin
    {
        public const string FirewallRule = "vpn-keeper";

        public static bool IsElevated()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch { return false; }
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
            return p;
        }

        // Launch the elevated worker (add the rule, or "remove" to delete it);
        // a UAC prompt appears. 0 applied, 1 the worker reported a problem,
        // -1 the prompt was declined.
        public static int Elevate(AdminPlan plan) { return Elevate(plan.ToArgs()); }
        public static int ElevateRemove() { return Elevate("remove"); }

        static int Elevate(string args)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(Config.InstalledExe, "netsetup " + args) { UseShellExecute = true, Verb = "runas" };
                using (Process p = Process.Start(psi))
                {
                    p.WaitForExit();
                    return p.ExitCode == 0 ? 0 : 1;
                }
            }
            catch (Win32Exception) { return -1; }   // user said No to UAC
        }

        // The elevated worker: add the firewall rule from args, or remove it.
        // Reads no config, so it does not matter which account UAC elevated to.
        public static int ApplyFromArgs(string[] args)
        {
            if (!IsElevated()) { Log.Error("netsetup needs administrator rights"); return 1; }
            bool remove = Array.IndexOf(args, "remove") >= 0;
            Run("netsh", "advfirewall firewall delete rule name=\"" + FirewallRule + "\"");   // ignore result
            if (remove) return 0;

            int port = 0;
            string remote = "LocalSubnet";
            foreach (string a in args)
            {
                if (a.StartsWith("port=")) int.TryParse(a.Substring(5), out port);
                else if (a.StartsWith("remoteip=")) remote = a.Substring(9);
            }
            if (port < 1 || port > 65535) { Log.Error("netsetup: bad port"); return 1; }
            return Run("netsh", "advfirewall firewall add rule name=\"" + FirewallRule + "\" dir=in action=allow protocol=TCP localport="
                + port + " remoteip=" + remote) ? 0 : 1;
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
