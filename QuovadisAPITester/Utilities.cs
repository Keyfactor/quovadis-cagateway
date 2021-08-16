using System;
using System.IO;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CAProxy.AnyGateway.Models;

namespace QuovadisAPITester
{
    public static class Utilities
    {
        public static string BuildSignedCmsStructure(string p12FileLocation, string p12Password, byte[] dataToSign)
        {
            //Retrieve web service signing certificate
            X509Certificate2 signingCert = null;
            var cert2Collection = new X509Certificate2Collection();
            cert2Collection.Import(p12FileLocation, p12Password, X509KeyStorageFlags.Exportable);
            foreach (var cert in cert2Collection)
            {
                if (!cert.HasPrivateKey) continue;
                signingCert = cert;
            }
            //Generate signed CMS payload
            var contentInfo = new ContentInfo(dataToSign);
            var signedCms = new SignedCms(contentInfo);
            var cmsSigner = new CmsSigner(signingCert);
            signedCms.ComputeSignature(cmsSigner);
            //Create base64 encoded signed CMS payload
            byte[] signedStructure = signedCms.Encode();
            var encodedText = Convert.ToBase64String(signedStructure);
            return encodedText;
        }

        public static TextReader GetTemplateCsr(string templateId)
        {
            return File.OpenText($"{Directory.GetCurrentDirectory()}\\Csrs\\{templateId}.csr");
        }

        public static EnrollmentProductInfo GetEnrollmentParameters(string templateId)
        {
            EnrollmentProductInfo productInfo = new EnrollmentProductInfo();

            switch (templateId)
            {
                case "2166":
                    productInfo.ProductParameters.Add("Admin Email", "brian.hill@keyfactor.com");
                    productInfo.ProductParameters.Add("Password", "Password12!");
                    productInfo.ProductParameters.Add("ConfirmPassword", "Password12!");
                    productInfo.ProductParameters.Add("Organisation Name", "KeyFactor");
                    break;
                case "2150":
                    productInfo.ProductParameters.Add("Subscriber Email", "bhill@keyfactor.com");
                    productInfo.ProductParameters.Add("Organisation Name", "KeyFactor");
                    break;
                case "2149":
                    productInfo.ProductParameters.Add("Admin Email", "brian.hill@keyfactor.com");
                    productInfo.ProductParameters.Add("Password", "Password12!");
                    productInfo.ProductParameters.Add("ConfirmPassword", "Password12!");
                    productInfo.ProductParameters.Add("Organisation Name", "KeyFactor");
                    productInfo.ProductParameters.Add("Country", "US");
                    break;
            }

            return productInfo;
        }

        public static string AddSerialNumberDashes(string s, char c, int n)
        {
            StringBuilder sb = new StringBuilder(s.Length + (s.Length % n) + 1);
            for (int i = 1; i <= s.Length; ++i)
            {
                sb.Append(s[i-1]);
                if (i % n == 0) sb.Append(c);
            }
            return sb.ToString();
        }
    }
}

