using System;
using System.IO;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Threading.Tasks;
using System.Xml.Serialization;
using CSS.Common.Logging;
using Keyfactor.AnyGateway.Quovadis.Client.XSDs;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;

namespace Keyfactor.AnyGateway.Quovadis.Client.Operations
{
    public class Revocation:LoggingClientBase
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
            try
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

                var reqWriter = new StringWriter();
                var reqSerializer = new XmlSerializer(typeof(RevokeCertificateBySerialNoRequestType));
                reqSerializer.Serialize(reqWriter, revokeRequest);
                Logger.Trace("Quovadis Revoke Cert Request : " + reqWriter);

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

                Logger.Trace("Quovadis Revoke Cert Signed Request : " + signedRequest);

                var certStatusResponse = Task.Run(async () =>
                    await quovadisClient.RevokeCertificateBySerialNoAsync(APIVersion.v1_0, ContentEncoding.UTF8,
                        signedRequest)).Result;

                var resWriter = new StringWriter();
                var resSerializer = new XmlSerializer(typeof(RevokeCertificateBySerialNoResponse1));
                resSerializer.Serialize(resWriter, certStatusResponse);
                Logger.Trace("Quovadis Revoke Cert Response : " + resWriter);

                return certStatusResponse;
            }
            catch (Exception e)
            {
                Logger.Error($"Unexpected Exception in Revocation.RevokeCertificate {e.Message}");
                throw;
            }
        }

        private RevokeCerticateBySerialNoRevocationReason GetRevokeReason(int revokeReason)
        {
            try
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
            catch (Exception e)
            {
                Logger.Error($"Unexpected Exception in Revocation.GetRevokeReason {e.Message}");
                throw;
            }
        }
    }
}
