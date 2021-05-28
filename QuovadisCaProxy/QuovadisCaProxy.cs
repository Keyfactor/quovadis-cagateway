using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CAProxy.AnyGateway;
using CAProxy.AnyGateway.Interfaces;
using CAProxy.AnyGateway.Models;
using CAProxy.Common;
using CSS.PKI;
using System.Xml.Serialization;

namespace Keyfactor.AnyGateway.Quovadis
{
    public class QuovadisCaProxy : BaseCAConnector
    {
        private readonly RequestManager _requestManager;

        public QuovadisCaProxy()
        {
            _requestManager = new RequestManager();
        }


        public bool EnableTemplateSync { get; set; }

        public override int Revoke(string caRequestId, string hexSerialNumber, uint revocationReason)
        {
            RevokeCertificateRequestType rt=new RevokeCertificateRequestType();
            CertificateServicesSoapClient client= new CertificateServicesSoapClient();

            var x = new XmlSerializer(rt.GetType());
            byte[] bytes;
            using (MemoryStream stream = new MemoryStream())
            {
                x.Serialize(stream, rt);
                bytes = stream.ToArray();
            }

            var signedRequest = _requestManager.BuildSignedCmsStructure("", "", bytes);

            var revokeResponse =
                Task.Run(async () => await client.RevokeSSLCertAsync(APIVersion.v2_0,ContentEncoding.UTF8, signedRequest)).Result;

            if (revokeResponse.RevokeSSLCertResponse.Result == RevokeResultType.RevocationRequestSuccessful)
            {
                return Convert.ToInt32(PKIConstants.Microsoft.RequestDisposition.REVOKED);
            }

            throw new Exception("Revoke failed");

        }

        [Obsolete]
        public override void Synchronize(ICertificateDataReader certificateDataReader,
            BlockingCollection<CertificateRecord> blockingBuffer,
            CertificateAuthoritySyncInfo certificateAuthoritySyncInfo, CancellationToken cancelToken,
            string logicalName)
        {
        }

        public override void Synchronize(ICertificateDataReader certificateDataReader,
            BlockingCollection<CAConnectorCertificate> blockingBuffer,
            CertificateAuthoritySyncInfo certificateAuthoritySyncInfo,
            CancellationToken cancelToken)
        {
            throw new InvalidOperationException();
        }

        [Obsolete]
        public override EnrollmentResult Enroll(string csr, string subject, Dictionary<string, string[]> san,
            EnrollmentProductInfo productInfo,
            PKIConstants.X509.RequestFormat requestFormat, RequestUtilities.EnrollmentType enrollmentType)
        {
            return null;
        }

        public override EnrollmentResult Enroll(ICertificateDataReader certificateDataReader, string csr,
            string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo,
            PKIConstants.X509.RequestFormat requestFormat, RequestUtilities.EnrollmentType enrollmentType)
        {
            throw new InvalidOperationException();
        }


        
        public override CAConnectorCertificate GetSingleRecord(string caRequestId)
        {
            throw new InvalidOperationException();
        }

        public override void Initialize(ICAConnectorConfigProvider configProvider)
        {
            throw new InvalidOperationException();
        }

        public override void Ping()
        {
        }

        public override void ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
        }

        public override void ValidateProductInfo(EnrollmentProductInfo productInfo,
            Dictionary<string, object> connectionInfo)
        {
        }
    }
}