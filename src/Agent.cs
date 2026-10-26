using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace VpnKeeper
{
    // The long-running part: keeps the PC awake, serves the proxy, and runs
    // the VPN watchdog forever. Nothing in here may end the process, except
    // a new .exe being installed.
    static class Agent
    {
        public const string Mutex = @"Local\vpn-keeper-agent";   // one agent per Windows session

        [DllImport("kernel32.dll")]
        static extern uint SetThreadExecutionState(uint flags);
        const uint EsContinuous = 0x80000000, EsSystemRequired = 0x00000001;

        // Idle sleep would cut the network and the VPN. This blocks it while the
        // calling thread's process runs (like a video player does); the screen
        // may still lock. The supervisor holds it too, so an agent restart is
        // never a gap: on a long-idle PC, Windows sleeps the moment none is held.
        public static void BlockSleep()
        {
            if (SetThreadExecutionState(EsContinuous | EsSystemRequired) == 0) Log.Warn("could not block idle sleep");
        }

        public static bool Running()
        {
            System.Threading.Mutex m;
            if (!System.Threading.Mutex.TryOpenExisting(Mutex, out m)) return false;
            m.Dispose();
            return true;
        }

        public static void Run(Config cfg)
        {
            Log.Info("vpn-keeper " + BuildInfo.Version + " starting");
            foreach (string p in cfg.Problems()) Log.Error("config: " + p + " (run vpn-keeper setup)");

            BlockSleep();
            Proxy proxy = new Proxy(cfg.Port, new Rules(cfg.Clients), new Rules(cfg.Allow), Watchdog.Status.Report);
            proxy.SavePassword = Watchdog.SavePassword;
            proxy.PasswordAsked = Watchdog.Status.Asking;
            proxy.Start();

            string exe = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName, stamp = ExeStamp(exe);
            while (true)
            {
                // 'vpn-keeper update' swapped in a new .exe: exit, and the
                // supervisor starts the new one.
                if (ExeStamp(exe) != stamp)
                {
                    Log.Info("a new vpn-keeper.exe was installed; restarting on it");
                    proxy.Stop();
                    return;
                }
                int wait;
                try { wait = Watchdog.Tick(cfg); }
                catch (Exception e)
                {
                    Log.Error("watchdog: " + e.Message);
                    Log.Debug(e.ToString());
                    wait = 30;
                }
                Thread.Sleep(wait * 1000);
            }
        }

        // Changes when the file at that path is replaced.
        public static string ExeStamp(string path)
        {
            try { FileInfo f = new FileInfo(path); return f.Length + "@" + f.LastWriteTimeUtc.Ticks; }
            catch (IOException) { return ""; }
        }
    }
}
