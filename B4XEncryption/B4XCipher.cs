//.net DLL class to allow encryption and decryption of data for use with the B4XEncryption library.
//Ported from the original Java supplied by Erel on the B4X.com forum.

using System;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Modes;

namespace B4XEncryption
{
    public static class B4XCipher
    {

        /// <summary>
        /// Decrypts data previously encrypted using the B4XEncryption methods, either via this DLL or from within B4i/B4A/B4J
        /// </summary>
        /// <param name="Data">Data must be supplied in UTF-8 format</param>
        /// <param name="Password">Password used to Encrypt the data previously.</param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] Data, String Password)
        {

            byte[] salt = new byte[8];

            byte[] iv = new byte[16];

            Array.Copy(Data, 0, salt, 0, 8);

            Array.Copy(Data, 8, iv, 0, 16);

            Pkcs5S2ParametersGenerator pGen = new Pkcs5S2ParametersGenerator(new Sha1Digest());

            byte[] pkcs12PasswordBytes = System.Text.Encoding.UTF8.GetBytes(Password);

            pGen.Init(pkcs12PasswordBytes, salt, 1024);

            CbcBlockCipher aesCBC = new CbcBlockCipher(new AesEngine());

            ParametersWithIV aesCBCParams = new ParametersWithIV(pGen.GenerateDerivedParameters(128), iv);

            aesCBC.Init(false, aesCBCParams);

            PaddedBufferedBlockCipher aesCipher = new PaddedBufferedBlockCipher(aesCBC,
                new Pkcs7Padding());

            aesCipher.Init(false, (pGen.GenerateDerivedParameters(128)));

            byte[] plainTemp = new byte[aesCipher.GetOutputSize(Data.Length - 24)];

            int offset = aesCipher.ProcessBytes(Data, 24, Data.Length - 24, plainTemp, 0);

            int last = aesCipher.DoFinal(plainTemp, offset);

            byte[] plain = new byte[offset + last];

            Array.Copy(plainTemp, 0, plain, 0, plain.Length);

            return plain;
        }

        /// <summary>
        /// Encrypt routine that will provide a byte array in UTF-8 format. This data can be decrypted in B4A,B4i,B4J or using the Decrypt routine of this DLL.
        /// </summary>
        /// <param name="Data">Data to be Encrypted in UTF-8 format</param>
        /// <param name="Password">Password for the encryption.</param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] Data, String Password)
        {

            SecureRandom rnd = new SecureRandom();

            byte[] salt = new byte[8];

            rnd.NextBytes(salt);

            byte[] iv = new byte[16];

            rnd.NextBytes(iv);

            Pkcs5S2ParametersGenerator pGen = new Pkcs5S2ParametersGenerator(new Sha1Digest());

            byte[] pkcs12PasswordBytes = System.Text.Encoding.UTF8.GetBytes(Password);

            pGen.Init(pkcs12PasswordBytes, salt, 1024);

            CbcBlockCipher aesCBC = new CbcBlockCipher(new AesEngine());

            ParametersWithIV aesCBCParams = new ParametersWithIV(pGen.GenerateDerivedParameters(128), iv);

            aesCBC.Init(true, aesCBCParams);

            PaddedBufferedBlockCipher aesCipher = new PaddedBufferedBlockCipher(aesCBC,
                    new Pkcs7Padding());

            aesCipher.Init(true, (pGen.GenerateDerivedParameters(128)));

            byte[] plainTemp = new byte[aesCipher.GetOutputSize(Data.Length)];

            int offset = aesCipher.ProcessBytes(Data, 0, Data.Length, plainTemp, 0);

            int last = aesCipher.DoFinal(plainTemp, offset);

            byte[] plain = new byte[offset + last + 24];

            Array.Copy(salt, 0, plain, 0, 8);

            Array.Copy(iv, 0, plain, 8, 16);

            Array.Copy(plainTemp, 0, plain, 24, offset + last);

            return plain;

        }

    }



}
