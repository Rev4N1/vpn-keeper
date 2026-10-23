using System;
using System.Runtime.InteropServices;

namespace VpnKeeper
{
    // Reads generic credentials saved with:
    //   cmdkey /generic:vpn-keeper:vpn /user:<vpn user> /pass
    // They are encrypted for this Windows user (DPAPI); nothing is kept on disk here.
    static class Credentials
    {
        const int CredTypeGeneric = 1;

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

        [DllImport("advapi32.dll")]
        static extern void CredFree(IntPtr buffer);

        public static bool TryRead(string target, out string user, out string secret)
        {
            user = null;
            secret = null;
            IntPtr p;
            if (!CredRead(target, CredTypeGeneric, 0, out p)) return false;
            try
            {
                Credential c = (Credential)Marshal.PtrToStructure(p, typeof(Credential));
                user = c.UserName;
                secret = c.CredentialBlobSize > 0 ? Marshal.PtrToStringUni(c.CredentialBlob, c.CredentialBlobSize / 2) : "";
                return true;
            }
            finally
            {
                CredFree(p);
            }
        }
    }
}
