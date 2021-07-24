using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EnciphermentTools.Encipherment.Service
{
    public class Pbkdf2HelperService
    {
        private static byte[] CreateSaltBytes(int size)
        {
            var rng = new RNGCryptoServiceProvider();

            var salt = new byte[size];
            rng.GetBytes(salt);

            return salt;
        }

        private static bool SlowEquals(byte[] a, byte[] b)
        {
            var diff = (uint)a.Length ^ (uint)b.Length;

            for (int i = 0; i < a.Length && i < b.Length; i++)
                diff |= (uint)(a[i] ^ b[i]);

            return diff == 0;
        }

        public string CreateHash(string text)
        {
            var salt = CreateSaltBytes(8);
            var hmacService = new Pbkdf2HashService(text, salt, 20, "System.Security.Cryptography.HMACSHA512");
            var hash = hmacService.GetBytes(64);

            // Now prepend salt values so we can verify later
            var finalHashBytes = new byte[salt.Length + hash.Length];

            Array.Copy(salt, 0, finalHashBytes, 0, salt.Length);
            Array.Copy(hash, 0, finalHashBytes, salt.Length, hash.Length);

            return Convert.ToBase64String(finalHashBytes);
        }

        public bool VerifyHash(string text, string hash)
        {
            // convert encrypted password to bytes
            var hashBytes = Convert.FromBase64String(hash);

            // now get raw salt 
            var saltBytes = new byte[8];
            Array.Copy(hashBytes, 0, saltBytes, 0, 8);

            // Generate new Hash using the salt from orginal hash
            var hashService = new Pbkdf2HashService(text, saltBytes, 20, "System.Security.Cryptography.HMACSHA512");
            var newHash = hashService.GetBytes(64); // depending on algorithm (SHA512 = 64, SHA256 = 32)

            // We need to add salt back to new hash, so we can compare them
            var finalHashBytes = new byte[saltBytes.Length + newHash.Length];

            Array.Copy(saltBytes, 0, finalHashBytes, 0, saltBytes.Length);
            Array.Copy(newHash, 0, finalHashBytes, saltBytes.Length, newHash.Length);

            // check for match with slow equals (to stop time attacks)
            var match = SlowEquals(finalHashBytes, Convert.FromBase64String(hash));

            return match;
        }
    }
}
