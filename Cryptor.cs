using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Cryptor
{
    public class Cryptor
    {
        // Base64
        public static string ConvertToBase64(string text)
        {
            byte[] textBytes = Encoding.UTF8.GetBytes(text);
            return Convert.ToBase64String(textBytes);
        }

        public static string ConvertFromBase64(string base64Text)
        {
            byte[] base64Bytes = Convert.FromBase64String(base64Text);
            return Encoding.UTF8.GetString(base64Bytes);
        }

        // Binary
        public static string ConvertToBinary(string text)
        {
            StringBuilder binaryStringBuilder = new StringBuilder();
            foreach (char c in text)
            {
                binaryStringBuilder.Append(Convert.ToString(c, 2).PadLeft(8, '0'));
            }
            return binaryStringBuilder.ToString();
        }

        public static string ConvertFromBinary(string binaryText)
        {
            List<byte> byteList = new List<byte>();
            for (int i = 0; i < binaryText.Length; i += 8)
            {
                byteList.Add(Convert.ToByte(binaryText.Substring(i, 8), 2));
            }
            return Encoding.UTF8.GetString(byteList.ToArray());
        }

        // AES Encryption
        public static string EncryptAES(string text, string key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32));
                aes.IV = new byte[16];

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(text);
                        }
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
        }

        public static string DecryptAES(string cipherText, string key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key.PadRight(32));
                aes.IV = new byte[16];

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(cipherText)))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }

        // MD5 Hashing
        public static string ComputeMD5Hash(string text)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(text));
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
        }

        // SHA-256 Hashing
        public static string ComputeSHA256Hash(string text)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(text));
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
            }
        }

        // RSA Encryption (for more advanced uses, including key management, additional implementation is required)
        public static string EncryptRSA(string text, RSAParameters publicKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKey);
                byte[] encryptedBytes = rsa.Encrypt(Encoding.UTF8.GetBytes(text), false);
                return Convert.ToBase64String(encryptedBytes);
            }
        }

        public static string DecryptRSA(string cipherText, RSAParameters privateKey)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateKey);
                byte[] decryptedBytes = rsa.Decrypt(Convert.FromBase64String(cipherText), false);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }

        // Caesar Cipher
        public static string EncryptCaesarCipher(string text, int shift)
        {
            StringBuilder encryptedText = new StringBuilder();

            foreach (char c in text)
            {
                if (char.IsLetter(c))
                {
                    char d = char.IsUpper(c) ? 'A' : 'a';
                    encryptedText.Append((char)(((c + shift - d) % 26) + d));
                }
                else
                {
                    encryptedText.Append(c);
                }
            }

            return encryptedText.ToString();
        }

        public static string DecryptCaesarCipher(string text, int shift)
        {
            return EncryptCaesarCipher(text, 26 - shift);
        }

        // Ukrainian Caesar Cipher
        public static string EncryptCaesarCipherUa(string text, int shift)
        {
            StringBuilder encryptedText = new StringBuilder();

            foreach (char c in text)
            {
                if (char.IsLetter(c))
                {
                    // Визначаємо діапазон літер
                    char d = 'а';
                    if (char.IsUpper(c))
                    {
                        d = 'А';
                    }

                    // Розраховуємо нову позицію літери
                    encryptedText.Append((char)(((c + shift - d) % 32) + d));
                }
                else
                {
                    encryptedText.Append(c);
                }
            }

            return encryptedText.ToString();
        }

        public static string DecryptCaesarCipherUa(string text, int shift)
        {
            return EncryptCaesarCipher(text, 32 - shift);
        }
    }
}