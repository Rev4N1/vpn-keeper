using System;
using System.Runtime.InteropServices;

namespace VpnKeeper
{
    // The VPN password and the TOTP seed, as generic entries in Windows
    // Credential Manager: encrypted for this Windows user (DPAPI), visible in
    // Control Panel > Credential Manager > Windows Credentials.
    static class Credentials
    {
        public const string Vpn = "vpn-keeper:vpn";   // user + password
        public const string Otp = "vpn-keeper:otp";   // the Base32 seed
        public const string Change = "vpn-keeper:change";   // a new password to change to when the VPN offers; empty = none
        public const string Held = "vpn-keeper:held";   // hash of a password the VPN refused, so a restart cannot retry it

        const int TypeGeneric = 1, PersistLocalMachine = 2;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct Credential
        {
            public int Flags;
            public int Type;
            public string TargetName;
            public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public int CredentialBlobSize;
            public IntPtr CredentialBlob;
            public int Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredRead(string target, int type, int flags, out IntPtr credential);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredWrite(ref Credential credential, int flags);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredDelete(string target, int type, int flags);

        [DllImport("advapi32.dll")]
        static extern void CredFree(IntPtr buffer);

        public static bool TryRead(string target, out string user, out string secret)
        {
            user = null;
            secret = null;
            IntPtr p;
            if (!CredRead(target, TypeGeneric, 0, out p)) return false;
            try
            {
                Credential c = (Credential)Marshal.PtrToStructure(p, typeof(Credential));
                user = c.UserName;
                secret = c.CredentialBlobSize > 0 ? Marshal.PtrToStringUni(c.CredentialBlob, c.CredentialBlobSize / 2) : "";
                return true;
            }
            finally { CredFree(p); }
        }

        public static void Write(string target, string user, string secret)
        {
            Credential c = new Credential();
            c.Type = TypeGeneric;
            c.TargetName = target;
            c.UserName = user;
            c.Persist = PersistLocalMachine;
            c.CredentialBlobSize = secret.Length * 2;
            c.CredentialBlob = Marshal.StringToCoTaskMemUni(secret);
            try
            {
                if (!CredWrite(ref c, 0))
                    throw new InvalidOperationException("could not save " + target + " in Credential Manager (error " + Marshal.GetLastWin32Error() + ")");
            }
            finally { Marshal.ZeroFreeCoTaskMemUnicode(c.CredentialBlob); }
        }

        public static bool Delete(string target)
        {
            return CredDelete(target, TypeGeneric, 0);
        }
    }
}
