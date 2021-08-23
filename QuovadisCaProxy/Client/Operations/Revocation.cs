using System;
using System.IO;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
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


        public RevokeCertificateBySerialNoResponse1 RevokeCertificate(string serialNumber, string issuerDn, string account, int revokeReason)
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
                Utilities.AddSerialNumberDashes(serialNumber, '-', 2).TrimEnd('-').ToLower();
            revokeRequest.IssuerDN =
                string.Join(",", issuerDn.Split(',').Reverse()).Trim().Replace(",C=", ", C=");

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

        private RevokeCerticateBySerialNoRevocationReason GetRevokeReason(int revokeReason)
        {
            switch (revokeReason)
            {
                case 1:
                    return RevokeCerticateBySerialNoRevocationReason.keyCompromise;
                case 3:
                    return RevokeCerticateBySerialNoRevocationReason.affiliationChanged;
                case 4:
                    return RevokeCerticateBySerialNoRevocationReason.superseded;
                default:
                    return RevokeCerticateBySerialNoRevocationReason.cessationOfOperation;
            }
        }
    }
}
