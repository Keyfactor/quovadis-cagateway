using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Serialization;
using Keyfactor.AnyGateway.Quovadis.Client.XSDs;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;

namespace Keyfactor.AnyGateway.Quovadis.Client.Operations
{
    public class Revocation
    {
        private readonly string baseUrl;
        private readonly string wsSigningCertDir;
        private readonly string wsSigningCertPwd;

        public Revocation(string baseUrl, string wsSigningCertDir, string wsSigningCertPwd)
        {
            this.baseUrl = baseUrl;
            this.wsSigningCertDir = wsSigningCertDir;
            this.wsSigningCertPwd = wsSigningCertPwd;
        }


        public RevokeCertificateBySerialNoResponse1 RevokeCertificate(X509Certificate2 actualCert, string account, string revokeReason)
        {
            var revokeRequest = new RevokeCertificateBySerialNoRequestType();
            var revokeAccount = new RevokeCertificateBySerialNoAccountInfo
            {
                Name = account,
                Organisation = account
            };
            revokeRequest.Account = revokeAccount;
            revokeRequest.DateTime = DateTime.Now;
            revokeRequest.Reason = GetRevokeReason(revokeReason);
            revokeRequest.SerialNo =
                Utilities.AddSerialNumberDashes(actualCert.SerialNumber, '-', 2).TrimEnd('-').ToLower();
            revokeRequest.IssuerDN =
                string.Join(",", actualCert.Issuer.Split(',').Reverse()).Trim().Replace(",C=", ", C=");

            var x = new XmlSerializer(revokeRequest.GetType());
            byte[] bytes;
            using (var stream = new MemoryStream())
            {
                x.Serialize(stream, revokeRequest);
                bytes = stream.ToArray();
            }

            Binding bind = new BasicHttpsBinding();
            var ep = new EndpointAddress(baseUrl);
            var quovadisClient = new CertificateServicesSoapClient(bind, ep);

            var signedRequest = Utilities.BuildSignedCmsStructure(wsSigningCertDir, wsSigningCertPwd, bytes);

            var certStatusResponse = Task.Run(async () =>
                await quovadisClient.RevokeCertificateBySerialNoAsync(APIVersion.v1_0, ContentEncoding.UTF8,
                    signedRequest)).Result;

            return certStatusResponse;

        }

        private RevokeCerticateBySerialNoRevocationReason GetRevokeReason(string revokeReason)
        {
            switch (revokeReason)
            {
                case "Key Compromise":
                    return RevokeCerticateBySerialNoRevocationReason.keyCompromise;
                case "Affiliation Changed":
                    return RevokeCerticateBySerialNoRevocationReason.affiliationChanged;
                case "Superseded":
                    return RevokeCerticateBySerialNoRevocationReason.superseded;
                default:
                    return RevokeCerticateBySerialNoRevocationReason.cessationOfOperation;
            }
        }
    }
}
