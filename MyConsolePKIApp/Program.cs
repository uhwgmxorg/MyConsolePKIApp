using System;
using System.Security.Cryptography;
using System.Text;

namespace MyConsolePKIApp
{
    class Program
    {
        static int KEY_SIZE = 512;
        static bool HEX_STRING_WITH_DASHES = true;

        static void Main(string[] args)
        {
            Console.WriteLine($"START MyConsolePKIApp in .Net 5.0 Version {System.Reflection.Assembly.GetExecutingAssembly().GetName().Version}\n");

            string textToEncrypt;
            //               0000000001111111111222222222233333333334444
            //               1234567890123456789012345678901234567890123
            textToEncrypt = "mykey";

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(KEY_SIZE);
            string pubkey = rsa.ToXmlString(false);
            string prikey = rsa.ToXmlString(true);
            // This shows the public and private keys as XML Structs
            //Console.WriteLine("Public key:");
            //Console.WriteLine(pubkey + "\n");
            //Console.WriteLine("Private key:");
            //Console.WriteLine(prikey + "\n");

            Console.WriteLine("Original Text and orginal Text as Hex String:");
            Console.WriteLine(textToEncrypt);
            Console.WriteLine(StringToHexString(textToEncrypt, HEX_STRING_WITH_DASHES) + "\n");

            byte[] encryptTextAsByteArray = RSAEncrypt(textToEncrypt, pubkey);
            Console.WriteLine("Encrypted Text (as HEX String):");
            Console.WriteLine(ByteArrayToHexString(encryptTextAsByteArray, HEX_STRING_WITH_DASHES) + "\n");

            byte[] decryptTextAsByteArry = RSADecrypt(encryptTextAsByteArray, prikey);
            Console.WriteLine("Decrypted Text and decrypted Text as Hex String:");
            Console.WriteLine(Encoding.Unicode.GetString(decryptTextAsByteArry));
            Console.WriteLine(StringToHexString(Encoding.Unicode.GetString(decryptTextAsByteArry), HEX_STRING_WITH_DASHES));
            Console.WriteLine("Hex String back to String:");
            Console.WriteLine(HexStringToString(StringToHexString(Encoding.Unicode.GetString(decryptTextAsByteArry), HEX_STRING_WITH_DASHES)) + "\n");

            Console.WriteLine("END.");
        }

        public static byte[] RSAEncrypt(string textToEncrypt, string publicKey)
        {
            byte[] plaintext = Encoding.Unicode.GetBytes(textToEncrypt);
            byte[] encryptedData;
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKey);
            encryptedData = rsa.Encrypt(plaintext, true);
            rsa.Dispose();
            return encryptedData;
        }

        public static byte[] RSADecrypt(byte[] ciphertext, string privatKey)
        {
            byte[] decryptedData;
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(privatKey);
            decryptedData = rsa.Decrypt(ciphertext, true);
            rsa.Dispose();
            return decryptedData;
        }

        public static string ByteArrayToHexString(byte[] ba, bool withDashes = true)
        {
            if (!withDashes)
                return BitConverter.ToString(ba).Replace("-", "");
            else
                return BitConverter.ToString(ba).Replace("-", "-");
        }

        public static string StringToHexString(string str, bool withDashes = true)
        {
            byte[] ba = Encoding.Default.GetBytes(str);
            string hexString = BitConverter.ToString(ba);
            if(!withDashes)
                hexString = hexString.Replace("-", "");
            return hexString;
        }

        public static string HexStringToString(string hex)
        {
            hex = hex.Replace("-", "");
            byte[] raw = new byte[hex.Length / 2];
            for (int i = 0; i < raw.Length; i++)
                raw[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            
            return Encoding.ASCII.GetString(raw);
        }
    }
}