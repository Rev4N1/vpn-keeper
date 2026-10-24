// vpn-keeper - keeps a SonicWall Connect Tunnel VPN logged in on this
// Windows PC and shares it with other machines through a small HTTP proxy.
//
// C# 5 / .NET Framework 4.8, so it builds with the csc.exe that ships with
// Windows: no SDK, no packages, one .exe.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace VpnKeeper
{
    static class Program
    {
        const string Usage =
@"vpn-keeper " + BuildInfo.Version + @"

  vpn-keeper setup       set up or update (asks; Enter keeps the current values)
  vpn-keeper status      how everything is, and what to fix
  vpn-keeper uninstall   stop it and remove it from this PC
  vpn-keeper run         run in this window, log on screen (for testing; Ctrl+C stops)";

        const string SupervisorMutex = @"Local\vpn-keeper";   // one supervisor per Windows session

        [DllImport("kernel32.dll")]
        static extern bool FreeConsole();

        static int Main(string[] args)
        {
            string cmd = args.Length > 0 ? args[0].TrimStart('-', '/').ToLowerInvariant() : "";
            try
            {
                switch (cmd)
                {
                    case "start": return Supervise();          // what autostart runs
                    case "agent": return RunAgent(false);      // started by the supervisor
                    case "run": Log.Echo = true; return RunAgent(true);
                    case "setup": return Setup.Run();
                    case "status": return Setup.Status();
                    case "uninstall": return Setup.Uninstall();
                    case "version": Console.WriteLine(BuildInfo.Version); return 0;
                }
                Console.WriteLine(Usage);
                return cmd.Length == 0 || cmd == "help" || cmd == "h" || cmd == "?" ? 0 : 2;
            }
            catch (Exception e)
            {
                Log.Echo = true;
                Log.Error(cmd + ": " + e.Message);
                Log.Debug(e.ToString());
                return 1;
            }
        }

        // Runs the agent as a child process and starts it again if it ever
        // exits, so a crash costs seconds, not the rest of the day.
        static int Supervise()
        {
            FreeConsole();   // started from the Startup shortcut: no window
            bool created;
            using (Mutex m = new Mutex(true, SupervisorMutex, out created))
            {
                if (!created) return 0;   // already running in this session
                string exe = Process.GetCurrentProcess().MainModule.FileName;
                Log.Info("supervisor started");
                while (true)
                {
                    // Nothing in here may throw out of the loop, or the agent
                    // would stop being restarted until the next logon.
                    try
                    {
                        using (Process p = Process.Start(new ProcessStartInfo(exe, "agent") { UseShellExecute = false, CreateNoWindow = true }))
                        {
                            p.WaitForExit();
                            Log.Warn("agent exited (code " + p.ExitCode + "); starting it again in 10 s");
                        }
                    }
                    catch (Exception e) { Log.Error("supervisor could not start the agent: " + e.Message); }
                    Thread.Sleep(10000);
                }
            }
        }

        static int RunAgent(bool foreground)
        {
            using (Mutex m = new Mutex(false, Agent.Mutex))
            {
                bool mine;
                try { mine = m.WaitOne(foreground ? 0 : Timeout.Infinite); }
                catch (AbandonedMutexException) { mine = true; }   // the previous agent died; take over
                if (!mine)
                {
                    Console.WriteLine("vpn-keeper is already running in the background. Stop it first: vpn-keeper uninstall");
                    return 3;
                }
                Agent.Run(Config.Load());
                return 0;
            }
        }
    }
}
