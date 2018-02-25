using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using B4XEncryption;

namespace B4XEncrptionTest
{
    class Program
    {
        static void Main(string[] args)
        {

            String Data = "Data to Encrypt";
            String Password = "Password";

            //Encrypt the data
            Byte[] EncryptedBytes= B4XCipher.Encrypt(Encoding.Unicode.GetBytes(Data), Password);

            //Decrypting the encrypted data
            Byte[] DecryptedBytes = B4XCipher.Decrypt(EncryptedBytes, Password);

            String DecryptedData;
            DecryptedData=Encoding.Unicode.GetString(DecryptedBytes);

        }
    }
}
