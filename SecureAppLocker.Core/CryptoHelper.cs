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

            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
            {
                byte[] hash = pbkdf2.GetBytes(HashSize);
                return (Convert.ToBase64String(hash), Convert.ToBase64String(salt));
            }
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
                using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
                {
                    byte[] hash = pbkdf2.GetBytes(HashSize);
                    return Convert.ToBase64String(hash) == storedHash;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}
