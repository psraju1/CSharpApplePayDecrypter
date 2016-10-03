using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using ApplePayDecrypter.Definition;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace ApplePayDecrypter
{
    public class ApplePay
    {
        private ApplePayRequest applePayRequest = null;
        private readonly byte[] symmetricIv;

        public ApplePay(ApplePayRequest applePayRequest)
        {
            this.applePayRequest = applePayRequest;
            symmetricIv = Hex.Decode("00000000000000000000000000000000");
        }

        public string Decrypt()
        {
            var privateKey = GetMerchantPrivateKey(applePayRequest.PrivateKeyBytes);
            byte[] ephemeralPublicKey = Base64.Decode(applePayRequest.ApplePayHeader.EphemeralPublicKey);
            var publicKey = GetPublicKeyParameters(ephemeralPublicKey);

            byte[] sharedSecretBytes = GenerateSharedSecret(privateKey, publicKey);
            byte[] encryptionKeyBytes = RestoreSymmertricKey(sharedSecretBytes);

            byte[] decryptedBytes = DoDecrypt(Base64.Decode(applePayRequest.Data), encryptionKeyBytes);
            string decryptedString = System.Text.Encoding.Default.GetString(decryptedBytes);

            return string.Empty;
        }

        public RSACryptoServiceProvider GetPrivateKeyFromP12File()
        {
            X509Certificate2 cert = new X509Certificate2(applePayRequest.P12Path, applePayRequest.P12FilePassword, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
            RSACryptoServiceProvider crypt = (RSACryptoServiceProvider)cert.PrivateKey;
            return crypt;
        }

        public ECPublicKeyParameters GetPublicKeyParameters(byte[] ephemeralPublicKeyBytes)
        {
            return (ECPublicKeyParameters)PublicKeyFactory.CreateKey(ephemeralPublicKeyBytes);
        }

        public static ECPrivateKeyParameters GetMerchantPrivateKey(byte[] privateKeyBite)
        {
            var akp = PrivateKeyFactory.CreateKey(privateKeyBite);
            return (ECPrivateKeyParameters)akp;
        }

        private byte[] GenerateSharedSecret(ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKeys)
        {
            ECPrivateKeyParameters keyParams = privateKey;
            IBasicAgreement agree = AgreementUtilities.GetBasicAgreement("ECDH");
            agree.Init(keyParams);
            BigInteger sharedSecret = agree.CalculateAgreement(publicKeys);
            return sharedSecret.ToByteArrayUnsigned();
        }

        protected byte[] RestoreSymmertricKey(byte[] sharedSecretBytes)
        {
            byte[] merchantIdentifier = GetHashSha256Bytes("2.16.840.1.101.3.4.1.46");//applePayRequest.MerchantIdentifier);

            ConcatenationKdfGenerator generator = new ConcatenationKdfGenerator(new Sha256Digest());
            byte[] COUNTER = { 0x00, 0x00, 0x00, 0x01 };
            byte[] algorithmIdBytes = Encoding.UTF8.GetBytes((char)0x0d + "id-aes256-GCM");
            byte[] partyUInfoBytes = Encoding.UTF8.GetBytes("Apple");
            byte[] partyVInfoBytes = merchantIdentifier;
            byte[] otherInfoBytes = Combine(Combine(Combine(algorithmIdBytes, partyUInfoBytes), COUNTER), partyVInfoBytes);

            generator.Init(new KdfParameters(sharedSecretBytes, otherInfoBytes));
            byte[] encryptionKeyBytes = new byte[16];
            generator.GenerateBytes(encryptionKeyBytes, 0, encryptionKeyBytes.Length);
            return encryptionKeyBytes;
        }

        private byte[] DoDecrypt(byte[] cipherData, byte[] encryptionKeyBytes)
        {
            byte[] output;
            try
            {
                KeyParameter keyparam = ParameterUtilities.CreateKeyParameter("AES", encryptionKeyBytes);
                ParametersWithIV parameters = new ParametersWithIV(keyparam, symmetricIv);
                IBufferedCipher cipher = GetCipher();
                cipher.Init(false, parameters);
                try
                {
                    output = cipher.DoFinal(cipherData);
                }
                catch (Exception ex)
                {
                    throw new ApplicationException("Invalid Data");
                }
            }
            catch (Exception ex)
            {
                throw new ApplicationException("There was an error occured when decrypting message.");
            }

            return output;
        }

        public IBufferedCipher GetCipher()
        {
            return CipherUtilities.GetCipher("AES/GCM/NoPadding");
        }



        private static byte[] GetHashSha256Bytes(string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            SHA256Managed hashstring = new SHA256Managed();
            byte[] hash = hashstring.ComputeHash(bytes);
            return hash;
        }

        protected static byte[] Combine(byte[] first, byte[] second)
        {
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

    }
}
