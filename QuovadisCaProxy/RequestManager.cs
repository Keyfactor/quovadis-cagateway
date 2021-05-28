using System;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Keyfactor.AnyGateway.Quovadis
{
    public class RequestManager
    {

        public string BuildSignedCmsStructure(string p12FileLocation,string p12Password,byte[] dataToSign)
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

    }
}