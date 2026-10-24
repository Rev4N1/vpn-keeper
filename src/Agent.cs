using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace VpnKeeper
{
    // The long-running part: keeps the PC awake, serves the proxy, and runs
    // the VPN watchdog forever. Nothing in here may end the process.
    static class Agent
    {
        public const string Mutex = @"Local\vpn-keeper-agent";   // one agent per Windows session

        [DllImport("kernel32.dll")]
        static extern uint SetThreadExecutionState(uint flags);
        const uint EsContinuous = 0x80000000, EsSystemRequired = 0x00000001;

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

            // Idle sleep would cut the network and the VPN. This blocks it while
            // the agent runs (like a video player does); the screen may still lock.
            if (SetThreadExecutionState(EsContinuous | EsSystemRequired) == 0) Log.Warn("could not block idle sleep");

            Proxy proxy = new Proxy(cfg.Port, new Rules(cfg.Clients), new Rules(cfg.Allow), Watchdog.Status.Report);
            proxy.Start();

            while (true)
            {
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
    }
}
