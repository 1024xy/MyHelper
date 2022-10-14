using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace MyTest.Base
{
    /// <summary>
    /// 加密帮助类
    /// </summary>
    public static class EncryptionHelper
    {
        /*
         * 暂用AES加密，后续可考虑以下方案
         * 
         * 
         * 
         * 客户端请求 AES的KEY每次随机生成
         * AES的KEY用RSA公钥加密，传输到服务端私钥解密 
         * 
         * 服务端回传数据 AES的KEY每次随机生成
         * AES的KEY用RSA私钥加密，传输到客户端公钥解密 
         * 
         */

        #region RSA 数据过大 加密慢 暂用AES


        /// <summary>
        /// 公钥
        /// </summary>
        private static readonly string RSAPublicKey = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDw0eikXyL0H6BctdCswfHQmiXxOfFOFoRCWDQZsIsfkRMuWknL1Mo5bG3vZrky+SpwuweMk9sreaDvKMKcYkP69tDmiDYJ9K5VJascyKA0cyFHReD0zLfpW37R5P12e4QNND+6BHxC5mUs4HckGKcNbGG4i9XsySjgkyjhz3QY6QIDAQAB";

        #region RSA公钥加密 私钥解密
        /// <summary>
        /// RSA公钥加密
        /// </summary>
        /// <param name="publickey">公钥</param>
        /// <param name="content">要加密的内容</param>
        /// <returns>加密后的内容</returns>
        public static string RSAEncrypt(string content, string publickey = "")
        {
            //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            //rsa.FromXmlString(RSAPublicKeyXML(publickey));
            //byte[] cipherbytes = rsa.Encrypt(Encoding.UTF8.GetBytes(content), false);

            //return Convert.ToBase64String(cipherbytes);

            publickey = RSAPublicKey;

            byte[] cipherbytes;

            //解决加密字符过长问题
            using (var rsaProvider = new RSACryptoServiceProvider())
            {
                var inputBytes = Encoding.UTF8.GetBytes(content);
                rsaProvider.FromXmlString(RSAPublicKeyXML(publickey));
                int bufferSize = (rsaProvider.KeySize / 8) - 11;
                var buffer = new byte[bufferSize];
                using (MemoryStream inputStream = new MemoryStream(inputBytes),
                     outputStream = new MemoryStream())
                {
                    while (true)
                    {
                        int readSize = inputStream.Read(buffer, 0, bufferSize);
                        if (readSize <= 0)
                        {
                            break;
                        }

                        var temp = new byte[readSize];
                        Array.Copy(buffer, 0, temp, 0, readSize);
                        var encryptedBytes = rsaProvider.Encrypt(temp, false);
                        outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);
                    }
                    //return Encoding.UTF8.GetString(outputStream.ToArray());
                    cipherbytes = outputStream.ToArray();
                }
            }
            //byte[] 转 16进制
            var encrypted = ByteToHexString(cipherbytes);

            //编码：string to base64
            var btdata = Encoding.UTF8.GetBytes(encrypted);
            string base64str_result = System.Convert.ToBase64String(btdata);

            return base64str_result;
        }

        /// <summary>
        /// RSA私钥解密
        /// </summary>
        /// <param name="privatekey">私钥</param>
        /// <param name="content">要解密的内容</param>
        /// <returns>解密后的内容</returns>
        public static string RSADecrypt(string content, string privatekey)
        {
            //解码 base64 to string
            byte[] bytes = Convert.FromBase64String(content);
            string str = Encoding.GetEncoding("UTF-8").GetString(bytes);

            //16进制 转 byte[]
            byte[] encrypted = HexStringToByte(str);

            //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            //rsa.FromXmlString(RSAPrivateKeyXML(privatekey));
            //byte[] cipherbytes = rsa.Decrypt(encrypted, false);

            byte[] cipherbytes;

            //解决加密字符过长问题
            using (var rsaProvider = new RSACryptoServiceProvider())
            {
                //var inputBytes = Convert.FromBase64String(content);
                rsaProvider.FromXmlString(RSAPrivateKeyXML(privatekey));
                int bufferSize = rsaProvider.KeySize / 8;
                var buffer = new byte[bufferSize];
                using (MemoryStream inputStream = new MemoryStream(encrypted),
                     outputStream = new MemoryStream())
                {
                    while (true)
                    {
                        int readSize = inputStream.Read(buffer, 0, bufferSize);
                        if (readSize <= 0)
                        {
                            break;
                        }
                        var temp = new byte[readSize];
                        Array.Copy(buffer, 0, temp, 0, readSize);
                        var rawBytes = rsaProvider.Decrypt(temp, false);
                        outputStream.Write(rawBytes, 0, rawBytes.Length);
                    }
                    //return Encoding.UTF8.GetString(outputStream.ToArray());
                    cipherbytes = outputStream.ToArray();
                }
            }
            return Encoding.UTF8.GetString(cipherbytes);
        }
        #endregion

        #region RSA私钥加密 公钥解密

        /// <summary>
        /// RSA私钥加密
        /// </summary>
        /// <param name="content">要解密的内容</param>
        /// <param name="privatekey">私钥</param>
        /// <returns>解密后的内容</returns>
        public static string RSAEncryptByPrivateKey(string content, string privatekey)
        {
            byte[] cipherbytes;

            //解决加密字符过长问题

            //加载私钥
            RSACryptoServiceProvider privateRsa = new RSACryptoServiceProvider();
            privateRsa.FromXmlString(RSAPrivateKeyXML(privatekey));

            //转换密钥
            AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetKeyPair(privateRsa);
            IBufferedCipher c = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding"); //使用RSA/ECB/PKCS1Padding格式

            //第一个参数为true表示加密，为false表示解密；第二个参数表示密钥
            c.Init(true, keyPair.Private);
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes(content);
            #region 分段加密
            int bufferSize = (privateRsa.KeySize / 8) - 11;
            byte[] buffer = new byte[bufferSize];
            //分段加密
            using (MemoryStream input = new MemoryStream(dataToEncrypt))
            using (MemoryStream ouput = new MemoryStream())
            {
                while (true)
                {
                    int readLine = input.Read(buffer, 0, bufferSize);
                    if (readLine <= 0)
                    {
                        break;
                    }
                    byte[] temp = new byte[readLine];
                    Array.Copy(buffer, 0, temp, 0, readLine);
                    byte[] encrypt = c.DoFinal(temp);
                    ouput.Write(encrypt, 0, encrypt.Length);
                }
                cipherbytes = ouput.ToArray();
            }
            #endregion
            //string strBase64 = Convert.ToBase64String(cipherbytes);

            //byte[] 转 16进制
            var encrypted = ByteToHexString(cipherbytes);

            //编码：string to base64
            var btdata = Encoding.UTF8.GetBytes(encrypted);
            string base64str_result = System.Convert.ToBase64String(btdata);

            return base64str_result;
        }

        /// <summary>
        /// RSA公钥解密
        /// </summary>
        /// <param name="content"></param>
        /// <param name="publickey"></param>
        /// <returns></returns>
        public static string RSADecryptByPublicKey(string content, string publickey = "")
        {
            publickey = RSAPublicKey;
            //解码 base64 to string
            byte[] bytes = Convert.FromBase64String(content);
            string str = Encoding.UTF8.GetString(bytes);

            //16进制 转 byte[]
            byte[] decrypted = HexStringToByte(str);

            byte[] cipherbytes;

            RSACryptoServiceProvider publicRsa = new RSACryptoServiceProvider();
            publicRsa.FromXmlString(RSAPublicKeyXML(publickey));

            //转换密钥
            AsymmetricKeyParameter keyPair = DotNetUtilities.GetRsaPublicKey(publicRsa);
            IBufferedCipher c = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding"); //使用RSA/ECB/PKCS1Padding格式

            //解决加密字符过长问题
            //第一个参数为true表示加密，为false表示解密；第二个参数表示密钥
            c.Init(false, keyPair);
            #region 分段解密
            int bufferSize = publicRsa.KeySize / 8;
            byte[] buffer = new byte[bufferSize];
            //分段解密
            using (MemoryStream input = new MemoryStream(decrypted), ouput = new MemoryStream())
            {
                while (true)
                {
                    int readLine = input.Read(buffer, 0, bufferSize);
                    if (readLine <= 0)
                    {
                        break;
                    }
                    byte[] temp = new byte[readLine];
                    Array.Copy(buffer, 0, temp, 0, readLine);
                    byte[] decrypt = c.DoFinal(temp);
                    ouput.Write(decrypt, 0, decrypt.Length);
                }
                cipherbytes = ouput.ToArray();
            }
            #endregion
            return Encoding.UTF8.GetString(cipherbytes);
        }

        #endregion

        #region RSA公钥 私钥转换
        /// <summary>    
        /// RSA公钥pem==>XML格式转换
        /// </summary>    
        /// <param name="publicKey">pem公钥</param>    
        /// <returns></returns>    
        private static string RSAPublicKeyXML(string publicKey)
        {
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
                    Convert.ToBase64String(publicKeyParam.Modulus.ToByteArrayUnsigned()),
                    Convert.ToBase64String(publicKeyParam.Exponent.ToByteArrayUnsigned()));
        }
        /// <summary>
        /// 私钥pem==>XML格式转换
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        private static string RSAPrivateKeyXML(string privateKey)
        {
            RsaPrivateCrtKeyParameters privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
            Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));
        }
        #endregion

        #region 进制转换
        /// <summary>
        /// 16进制字符转换为字节
        /// </summary>
        /// <param name="hs"></param>
        /// <returns></returns>
        private static byte[] HexStringToByte(string hs)
        {
            //将16进制秘钥转成字节数组
            var byteArray = new byte[hs.Length / 2];
            for (var x = 0; x < byteArray.Length; x++)
            {
                var i = Convert.ToInt32(hs.Substring(x * 2, 2), 16);
                byteArray[x] = (byte)i;
            }
            return byteArray;
        }
        /// <summary>
        /// 字节转换为16进制字符
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private static string ByteToHexString(byte[] data)
        {
            string strTemp = "";
            for (int i = 0; i < data.Length; i++)
            {
                string a = Convert.ToString(data[i], 16).PadLeft(2, '0');
                strTemp = strTemp + a;
            }
            return strTemp;
        }
        #endregion
        #endregion

        #region AES

        /// <summary>
        /// 获取密钥 必须是32字节
        /// </summary>
        private static string Key
        {
            get { return @"C0D2ACC1205B4028A4888CAC475FBE36"; }
        }

        /// <summary>
        /// AES加密
        /// </summary>
        /// <param name="plainStr">明文字符串</param>
        /// <returns>密文</returns>
        public static string AESEncrypt(string encryptStr)
        {
            byte[] keyArray = UTF8Encoding.UTF8.GetBytes(Key);
            byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes(encryptStr);
            RijndaelManaged rDel = new RijndaelManaged();
            rDel.Key = keyArray;
            rDel.Mode = CipherMode.ECB;
            rDel.Padding = PaddingMode.PKCS7;
            ICryptoTransform cTransform = rDel.CreateEncryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }

        /// <summary>
        /// AES解密
        /// </summary>
        /// <param name="encryptStr"></param>
        /// <returns></returns>
        public static string AESDEncrypt(string encryptStr)
        {
            byte[] keyArray = UTF8Encoding.UTF8.GetBytes(Key);
            byte[] toEncryptArray = Convert.FromBase64String(encryptStr);
            RijndaelManaged rDel = new RijndaelManaged();
            rDel.Key = keyArray;
            rDel.Mode = CipherMode.ECB;
            rDel.Padding = PaddingMode.PKCS7;
            ICryptoTransform cTransform = rDel.CreateDecryptor();
            byte[] resultArray = cTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            return UTF8Encoding.UTF8.GetString(resultArray);
        }

        #endregion
    }
}
