using System;
using System.Security.Cryptography;
using System.Text;

namespace SecureAppLocker.Core
{
    public static class CryptoHelper
    {
        public static byte[] ProtectLocalData(string secretData)
        {
            byte[] rawData = Encoding.UTF8.GetBytes(secretData);
            return ProtectedData.Protect(rawData, null, DataProtectionScope.LocalMachine);
        }

        public static string UnprotectLocalData(byte[] encryptedData)
        {
            byte[] rawData = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.LocalMachine);
            return Encoding.UTF8.GetString(rawData);
        }
    }
}
