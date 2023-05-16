using System;
using System.IO;
using System.Collections;
using System.Security.Cryptography;
using System.Text;

namespace OperationProtection
{
    public class OperationProtection
    {
        public byte[] ComputeSha256Hash(string data) {
            SHA256 sha256 = SHA256.Create();
            byte[] dataBytes = Encoding.ASCII.GetBytes(data);
            return sha256.ComputeHash(dataBytes);
        }

        public string DecodeBase64(string signatureBase64)
        {
            byte[] signatureBase64Bytes = System.Convert.FromBase64String(signatureBase64);
            return System.Text.Encoding.UTF8.GetString(signatureBase64Bytes);
        }

        public bool VerifySignature(string data, string signatureBase64)
        {
            string currentDir = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
            string validKeysDir = Path.Combine(currentDir, "valid-keys");
            string[] validKeyFilePaths = Directory.GetFiles(validKeysDir);
            byte[] hash = ComputeSha256Hash(data);
            byte[] signature = DecodeBase64(signatureBase64);

            foreach (string validKeyFilePath in validKeyFilePaths)
            {
                string keyData = File.ReadAllText(validKeyFilePath);
                RSA rsa = RSA.Create();
                rsa.ImportFromPem(keyData);

                RSAPKCS1SignatureDeformatter rsaDeformatter = new(rsa);
                rsaDeformatter.SetHashAlgorithm(nameof(SHA256));

                if (rsaDeformatter.VerifySignature(hash, signature))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
