using System;
using System.IO;
using System.Collections;
using System.Security.Cryptography;
using System.Text;

namespace OperationProtection
{
    public class OperationProtection
    {
        public bool VerifySignature(string data, string signatureBase64)
        {
            string currentDir = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
            string validKeysDir = Path.Combine(currentDir, "valid-keys");
            string[] validKeyFilePaths = Directory.GetFiles(validKeysDir);

            foreach (string validKeyFilePath in validKeyFilePaths)
            {
                string keyData = File.ReadAllText(validKeyFilePath);
                RSA rsa = RSA.Create();
                rsa.ImportFromPem(keyData);

                RSAPKCS1SignatureDeformatter rsaDeformatter = new(rsa);
                rsaDeformatter.SetHashAlgorithm(nameof(SHA256));

                if (rsaDeformatter.VerifySignature(hash, signedHash))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
