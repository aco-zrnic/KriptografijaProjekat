using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;

namespace Projekni
{
    class LogSign
    {
        string username, password, pathOfCert; //Za Logovanje korisnika u sistem!
        string creatHashPassword(string source)
        {
            using (MD5 md5Hash = MD5.Create())
            {
                string hash = GetMd5Hash(md5Hash, source);
                return hash;
            }
        }
        string GetMd5Hash(MD5 md5Hash, string input)
        {

            // Convert the input string to a byte array and compute the hash.
            byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Create a new Stringbuilder to collect the bytes
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data 
            // and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string.
            return sBuilder.ToString();
        }
        bool VerifyMd5Hash(MD5 md5Hash, string input, string hash)
        {
            // Hash the input.
            string hashOfInput = GetMd5Hash(md5Hash, input);

            StringComparer comparer = StringComparer.OrdinalIgnoreCase;

            if (0 == comparer.Compare(hashOfInput, hash))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        internal static byte[] ReadFile(string fileName)
        {
            FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read);
            int size = (int)f.Length;
            byte[] data = new byte[size];
            size = f.Read(data, 0, size);
            f.Close();
            return data;
        }
        bool certTesting()
        {
            Console.WriteLine("Unesite putanju do certifikata!");

            X509Certificate2 x509 = new X509Certificate2();
            pathOfCert = Console.ReadLine();
            //Create X509Certificate2 object from .pem file.

            try
            {
                byte[] rawData = ReadFile(pathOfCert);

                x509.Import(rawData);
                var cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(x509.GetRawCertData());
                bool[] keyUsage = cert.GetKeyUsage();
                foreach (bool key in keyUsage)
                {
                    Console.WriteLine("OK{0}", key);
                }


                byte[] buf = ReadFile("lista1.pem");
                X509CrlParser xx = new X509CrlParser();
                X509Crl ss = xx.ReadCrl(buf);

                var nextupdate = ss.NextUpdate;
                var isRevoked = ss.IsRevoked(cert);
                //Console.WriteLine("{0} {1}", nextupdate, isRevoked);

                DateTime dateNow = DateTime.Now; //Da uporedimo jel lista jos dalje aktivna!
                DateTime dateList = nextupdate.Value;
                if (dateNow.Date > dateList.Date)
                {
                    Console.WriteLine("Izabrata CRL lista je outOfDate,prosledite novu,za dalji rad!");
                    return false;
                }
                else if (isRevoked == true)
                {
                    Console.WriteLine("Certefikat je povucen i ne moze se koristit!\nZelite odabrati drugi certifikat");
                    string decision = Console.ReadLine();
                    if (decision == "Y" || decision == "y")
                    {
                        Console.Clear();
                        certTesting();
                    }
                    else
                        return false;
                }
                //DODATI OVDE JOS else if za provjeru za sta se key certifikata moze koristit!
                //i ako je uredan ispisati da je cert uredan
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine("Nepravilan odabir certifikata!\nZelite opet probati (Y/N)");
                string decision = Console.ReadLine();
                if (decision == "Y" || decision == "y")
                {
                    Console.Clear();
                    certTesting();
                }
                else
                    return false;
            }
            return true;
        }
        bool messagedialog ()
        {
            Console.WriteLine("Unesite username");
            username = Console.ReadLine();
        
            Console.WriteLine("Unesite password:");
            password = Console.ReadLine();

            try
            {
                using (StreamReader reader = new StreamReader("korisnici.txt"))
                {
                    string str = "";
                    MD5 md5Hash = MD5.Create();
                    bool decisionNumber = false; //ako ne nadje username da izbaci error;
                    while ((str = reader.ReadLine()) != null) //provjera korisnika
                    {
                        if(str.Contains(username))
                        {

                            str = str.Remove(0,str.LastIndexOf(" ")+1); //da string sadrzi samo hash
                            decisionNumber = VerifyMd5Hash(md5Hash, password, str);
                            
                        }
                    }
                    if (decisionNumber == false) 
                    {
                        Console.WriteLine("Nepravilan username ili password\nZelite opet probati (Y/N)");
                        string decision = Console.ReadLine();
                        if (decision == "Y" || decision == "y")
                        {
                            Console.Clear();
                            messagedialog();
                        }
                    }
                    else if(decisionNumber == true) //PROBATI URADITI BEZ ELSE IF,MALO OJACATI FUNCKIJU MESSAGEDIALOG
                    {
                        return certTesting();
                    }
                }
            }
            catch(IOException exception)
            {
                Console.WriteLine("File nije mogao biti procitan");
                Console.WriteLine(exception.Message);
                return false;
            }
            return false;

        }
        void encDecDecision()
        {
            EncryptDecSorc encryptDecSorc = new EncryptDecSorc();
            TransferOfFiles transferOfFiles = new TransferOfFiles();
            Console.WriteLine("(odaberite opciju)\n1.Enkripcija\n2.Dekripcija\n3.Posalji kriptovane file-ove\n4.Logout");
            string decisionEncDec = Console.ReadLine();
            if (decisionEncDec == "1")
            {
                SHA256CryptoServiceProvider sHA256 = new SHA256CryptoServiceProvider();
                MD5CryptoServiceProvider mD5 = new MD5CryptoServiceProvider();
                byte[] key, enc = null, hashOfData;

                Console.WriteLine("Odaberite algoritam za enkripciju file-a (1,2,3)\n1.AES256-CBC\n2.DES3-CBC\n3.RC2-ECB");
                string decision = Console.ReadLine();
                Console.WriteLine("Odaberite hash algoritam (1,2)\n1.MD5\n2.SHA256");
                string hashdecision, hashStringValueOfFile, pathOfHashedFile, pathOfCryptedSourceFile;
                hashdecision = Console.ReadLine();
                Console.WriteLine("Unesi putanju do Source-a kojeg zelis kriptovati");
                string sourcePath = Console.ReadLine();
                byte[] data = ReadFile(sourcePath);
                Console.WriteLine("Unesite sesijski kljuc.\nPAZLJIVO GA BIRAJTE!");
                string password = Console.ReadLine();

                //Uradi HASH teksta prije enkripcije!
                if (hashdecision == "1")
                {
                    hashStringValueOfFile = creatHashPassword(Encoding.UTF8.GetString(data));//ovo koristimo da uradimo hash file-a;

                }
                else
                {
                    hashStringValueOfFile = creatHashPassword(Encoding.UTF8.GetString(data)); //uradit za sha256
                    //  hashStringValueOfFile = sHA256.ComputeHash(data);
                }
                pathOfHashedFile = AppDomain.CurrentDomain.BaseDirectory + username + "\\hashOfSorcefile.txt"; //DODATI JOS NESTO U SLUCAJU DA IMA VISE HASHOFSOURCEFILE-OVA

                using (FileStream fs = File.Create(pathOfHashedFile)) //upis hasha u file
                {
                    hashOfData = Encoding.ASCII.GetBytes(hashStringValueOfFile);
                    fs.Write(hashOfData, 0, hashOfData.Length);
                }

                if (decision == "1")
                {
                    key = sHA256.ComputeHash(Encoding.UTF8.GetBytes(password));
                    enc = encryptDecSorc.EncryptAES256(data, key);
                }
                else if (decision == "2")
                {
                    key = mD5.ComputeHash(Encoding.UTF8.GetBytes(password));
                    enc = encryptDecSorc.EncryptDES3(data, key);
                }
                else if (decision == "3")
                {
                    key = mD5.ComputeHash(Encoding.UTF8.GetBytes(password));
                    enc = encryptDecSorc.EncryptRC2(data, key);
                }
                else
                {
                    Console.WriteLine("Nepravilan unos,Ponovite");
                    encDecDecision();
                    // enc= Enumerable.Repeat((byte)0x20, 4).ToArray(); //samo da enc moze radit u pathOfSourcefile (unassigned local variable)
                }

                //SACUVATI KRIPTOVAN SADRZAJ U FOLDERU USERA
                pathOfCryptedSourceFile = AppDomain.CurrentDomain.BaseDirectory + username + "\\" + DateTime.Now.ToString("hh-mm-ss-dd-MM-yyyy") + "cryptedSorcefile.txt";
                using (FileStream fs = File.Create(pathOfCryptedSourceFile)) //upis kriptovanog source-a u file
                {
                    fs.Write(enc, 0, enc.Length);
                }

                encryptDecSorc.RsaEncryptWithPublic(password, username, pathOfCert); //Enkripcija sa RSA public keyom

            }
            else if (decisionEncDec == "2")
            {
                encryptDecSorc.Decryption(username);
            }
            else if (decisionEncDec == "3")
            {
                Console.Clear();
                transferOfFiles.transfer(username);
            }
            else if(decisionEncDec == "4")
            {
                return;
            }
            else
            {
                Console.WriteLine("Nepravilan unos,Ponovite");
                encDecDecision();
            }
            Console.Clear();
            encDecDecision();
        }
        public void creatAccount()
        {
            string username, password;
            Console.WriteLine("Unesite username");
            username = Console.ReadLine();

            Console.WriteLine("Unesite password:");
            password = Console.ReadLine();

            string input = "",hashPassword;

            hashPassword = creatHashPassword(password); //da kreiramo Hash passworda
            input = username + " " + hashPassword;
            StreamWriter streamWriter = new StreamWriter("korisnici.txt", true);
            streamWriter.WriteLine(input);
            streamWriter.Close();

        
            Directory.CreateDirectory(username);
        }
        public void starupScreen()
        {
            Console.WriteLine("Dobrodosli u sistem!\n(odaberite opciju)\n1.Logovanje\n2.Kreiranje naloga");
            string decision;//odlucujemo da li da se logujemo ili kreiramo nalog;
            decision = Console.ReadLine();
            if (decision == "1")
            {
                Console.Clear();
                if (messagedialog() == true)
                {
                    Console.Clear();
                    encDecDecision();
                }
            }
            else if (decision == "2")
            {
                Console.Clear();
                creatAccount();
                Console.Clear();
                starupScreen();
            }
            else
            {
                Console.WriteLine("Nepravilan unos,ponovite!");
                starupScreen();
            }
        }
    }
    class EncryptDecSorc
    {
        private AesCryptoServiceProvider createProviderAES(byte[] key, byte[] IVector)
        {
            return new AesCryptoServiceProvider
            {
                KeySize = 256,
                BlockSize = 128,
                Key = key,
                IV = IVector,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC
            };
        }
        private TripleDESCryptoServiceProvider createProviderDES3(byte[] key, byte[] IVector)
        {
            return new TripleDESCryptoServiceProvider
            {
                KeySize = 128,
                BlockSize = 64,
                Key = key,
                IV = IVector,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC
            };


        }
        private RC2CryptoServiceProvider createProviderRC2(byte[] key)
        {
            return new RC2CryptoServiceProvider
            {
                KeySize = 128,
                BlockSize = 64,
                Key = key,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.ECB
            };
        }
        public byte[] EncryptRC2(byte[] data, byte[] key)
        {
            using (RC2CryptoServiceProvider csp = createProviderRC2(key))
            {
                ICryptoTransform encypter = csp.CreateEncryptor();
                return encypter.TransformFinalBlock(data, 0, data.Length);
            }
        }
        private byte[] DecryptRC2(byte[] data, byte[] key)
        {
            using (RC2CryptoServiceProvider csp = createProviderRC2(key))
            {
                ICryptoTransform decrypter = csp.CreateDecryptor();
                return decrypter.TransformFinalBlock(data, 0, data.Length);
            }
        }
        public byte[] EncryptDES3(byte[] data, byte[] key)
        {
            byte[] IV = { 67, 22, 3, 4, 55, 6, 77, 8 };
            using (TripleDESCryptoServiceProvider csp = createProviderDES3(key, IV))
            {
                ICryptoTransform encypter = csp.CreateEncryptor();
                return encypter.TransformFinalBlock(data, 0, data.Length);
            }
        }
        private byte[] DecryptDES3(byte[] data, byte[] key)
        {
            byte[] IV = { 67, 22, 3, 4, 55, 6, 77, 8 };
            using (TripleDESCryptoServiceProvider csp = createProviderDES3(key, IV))
            {
                ICryptoTransform decrypter = csp.CreateDecryptor();
                return decrypter.TransformFinalBlock(data, 0, data.Length);
            }
        }
        public byte[] EncryptAES256(byte[] data, byte[] key)
        {

            byte[] IV = { 67, 22, 3, 4, 55, 6, 77, 8, 1, 72, 33, 4, 55, 6, 7, 88 };
            using (AesCryptoServiceProvider csp = createProviderAES(key, IV))
            {
                ICryptoTransform encrypter = csp.CreateEncryptor();
                return encrypter.TransformFinalBlock(data, 0, data.Length);
            }
        }
        private byte[] DecryptAES256(byte[] data, byte[] key)
        {
            byte[] IV = { 67, 22, 3, 4, 55, 6, 77, 8, 1, 72, 33, 4, 55, 6, 7, 88 };
            using (AesCryptoServiceProvider csp = createProviderAES(key, IV))
            {
                ICryptoTransform decrypter = csp.CreateDecryptor();
                return decrypter.TransformFinalBlock(data, 0, data.Length);
            }
        }
        public string RsaEncryptWithPublic(string sessionKey, string username, string pathOfCert)
        {
            string pathOfCryptedSessionKeyFile;

            X509Certificate2 x509 = new X509Certificate2();
            //Create X509Certificate2 object from .pem file.
      
             byte[] rawData =LogSign.ReadFile(pathOfCert);

             x509.Import(rawData);
             var cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(x509.GetRawCertData());

           var bytesToEncrypt = Encoding.UTF8.GetBytes(sessionKey);
           var encryptEngine = new Pkcs1Encoding(new RsaEngine());            
           var keyParameter = cert.GetPublicKey();
           encryptEngine.Init(true, keyParameter);
           var encrypted = Convert.ToBase64String(encryptEngine.ProcessBlock(bytesToEncrypt, 0, bytesToEncrypt.Length));


            pathOfCryptedSessionKeyFile = AppDomain.CurrentDomain.BaseDirectory + username + "\\" + DateTime.Now.ToString("hh-mm-ss-dd-MM-yyyy") + "cryptedSessionKeyFile.txt"; //mozda ne potrebas .pem format,vidjeti u toku rada!!!
            /*using (FileStream fs = File.Create(pathOfCryptedSessionKeyFile)) //upis kriptovanog sesijskog kljuca u file!
            {
                fs.Write(Convert.FromBase64String(encrypted), 0, Convert.FromBase64String(encrypted).Length);
            }*/

            File.WriteAllText(pathOfCryptedSessionKeyFile, encrypted);

            return encrypted;//za sad nepotrebno
        }
        private void RsaDecryptWithPrivate(string pathOfRsaPrivateKey,string pathOfEncryptedSessionKey)
        {
            string encrypted = File.ReadAllText(pathOfEncryptedSessionKey);
            var bytesToDecrypt = Convert.FromBase64String(encrypted);

            AsymmetricCipherKeyPair keyPair;
            var decryptEngine = new Pkcs1Encoding(new RsaEngine());

            using (var reader = File.OpenText(pathOfRsaPrivateKey))
            {
                keyPair = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();

                decryptEngine.Init(false, keyPair.Private);
            }

            var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
            Console.WriteLine("{0}", decrypted);
        }
        public void Decryption(string logedUser)
        {
            string pathOfRsaPrivateKey="", pathOfEncryptedSessionKey="", privateKeyName, encryptedSessionKeyName;

            while (!File.Exists(pathOfRsaPrivateKey) && !File.Exists(pathOfEncryptedSessionKey))
            {
                Console.WriteLine("Unesite ime Private RSA kljuca!");
                privateKeyName = Console.ReadLine();
                Console.WriteLine("Unesite ime Encrypted Session kljuca");
                encryptedSessionKeyName = Console.ReadLine();
                pathOfRsaPrivateKey = AppDomain.CurrentDomain.BaseDirectory + logedUser + "\\" + privateKeyName;
                pathOfEncryptedSessionKey = AppDomain.CurrentDomain.BaseDirectory + logedUser + "\\" + encryptedSessionKeyName;
                Console.WriteLine("Unesene putanje nepostojeceg file-a!\nProbajte opet");
                Console.Clear();
            }
            RsaDecryptWithPrivate(pathOfRsaPrivateKey, pathOfEncryptedSessionKey);

        }

    }
    class TransferOfFiles
    {
        string resiver;
        string currentUser;
        public void transfer(string logedUser)
        {
            currentUser = logedUser;
            Console.WriteLine("Unesite ime korisnika koje zelite da posaljete file-ove!");
            resiver = Console.ReadLine();
            if (searchUserBase(resiver))
            {
                sendFiles();
            }
            else
                Console.WriteLine("Ne postoji taj korisnik!");
        }
        bool searchUserBase(string user)
        {
            try
            {
                string str;
                using (StreamReader reader = new StreamReader("korisnici.txt"))
                {
                    while ((str = reader.ReadLine()) != null) //provjera korisnika
                    {
                        if (str.Contains(user))
                        {
                            str = str.Remove(str.LastIndexOf(" ")); //da string sadrzi samo hash
                            if(str.Equals(user))
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            catch (IOException exception)
            {
                Console.WriteLine("File nije mogao biti procitan");
                Console.WriteLine(exception.Message);
                return false;
            }
            return false;
        }
        void sendFiles()
        {
            string targetPath = AppDomain.CurrentDomain.BaseDirectory + resiver;
            string sourcePath = AppDomain.CurrentDomain.BaseDirectory + currentUser;

            Console.WriteLine("Uniste ime hashFile-a koge saljete");
            string hashFileName = Console.ReadLine();
            Console.WriteLine("Uniste ime cryptedSourceFile-a koge saljete");
            string cryptedSourceFileName = Console.ReadLine();
            Console.WriteLine("Uniste ime cryptedSessionKeyFile-a koge saljete");
            string cryptedSessionKeyFileName = Console.ReadLine();

            string sourceFile1 = Path.Combine(sourcePath, hashFileName);
            string destFile1 = Path.Combine(targetPath, hashFileName);

            string sourceFile2 = Path.Combine(sourcePath, cryptedSourceFileName);
            string destFile2 = Path.Combine(targetPath, cryptedSourceFileName);

            string sourceFile3 = Path.Combine(sourcePath, cryptedSessionKeyFileName);
            string destFile3 = Path.Combine(targetPath, cryptedSessionKeyFileName);

            try
            {
                File.Copy(sourceFile1, destFile1, true);
                File.Copy(sourceFile2, destFile2, true);
                File.Copy(sourceFile3, destFile3, true);
            }
            catch (Exception e)
            {
                Console.WriteLine("{0}\nUnesite imena postojecih file-ova!", e);
                Console.Clear();
                sendFiles();
            }
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            LogSign logSign = new LogSign();
            logSign.starupScreen();
            Console.ReadKey();
        }
    }
}
