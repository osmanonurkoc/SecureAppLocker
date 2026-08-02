using System;
using System.Security.Cryptography;

namespace SecureAppLocker.Core
{
    public static class CryptoHelper
    {
        private const int Iterations = 100000;
        private const int HashSize = 32; // 256 bit
        private const int SaltSize = 16; // 128 bit

        public static (string Hash, string Salt) HashPassword(string password)
        {
            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
            return (Convert.ToBase64String(hash), Convert.ToBase64String(salt));
        }

        public static bool VerifyPassword(string password, string storedHash, string storedSalt)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(storedHash) || string.IsNullOrEmpty(storedSalt))
            {
                return false;
            }

            try
            {
                byte[] salt = Convert.FromBase64String(storedSalt);
                byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
                return Convert.ToBase64String(hash) == storedHash;
            }
            catch
            {
                return false;
            }
        }
    }
}
