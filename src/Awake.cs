using System;
using System.Runtime.InteropServices;

namespace VpnKeeper
{
    // Stops idle sleep for as long as the agent runs (the screen may still turn
    // off and lock). Sleep would cut the network and drop the VPN. Closing the
    // lid is a separate power setting that this cannot override.
    static class Awake
    {
        const uint EsContinuous = 0x80000000;
        const uint EsSystemRequired = 0x00000001;

        [DllImport("kernel32.dll")]
        static extern uint SetThreadExecutionState(uint flags);

        // Must be called from a thread that lives as long as the agent.
        public static void Hold()
        {
            if (SetThreadExecutionState(EsContinuous | EsSystemRequired) == 0)
                Log.Warn("could not prevent idle sleep");
            else
                Log.Info("idle sleep blocked while the agent runs");
        }
    }
}
