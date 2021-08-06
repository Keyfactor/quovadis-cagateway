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
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;

namespace Keyfactor.AnyGateway.Quovadis
{
    public class QuovadisCaProxy : BaseCAConnector
    {
        private readonly RequestManager _requestManager;

        public QuovadisCaProxy()
        {
            _requestManager = new RequestManager();
        }


        private CertificateServicesSoapClient QuovadisClient { get; set; }

        private string BaseUrl { get; set; }

        public override int Revoke(string caRequestId, string hexSerialNumber, uint revocationReason)
        {
            try
            {
                RevokeCertificateRequestType rt = new RevokeCertificateRequestType();

                var x = new XmlSerializer(rt.GetType());
                byte[] bytes;
                using (MemoryStream stream = new MemoryStream())
                {
                    x.Serialize(stream, rt);
                    bytes = stream.ToArray();
                }

                var signedRequest = _requestManager.BuildSignedCmsStructure("", "", bytes);

                var revokeResponse =
                    Task.Run(async () => await QuovadisClient.RevokeSSLCertAsync(APIVersion.v2_0, ContentEncoding.UTF8, signedRequest)).Result;

                if (revokeResponse.RevokeSSLCertResponse.Result.Equals(RevokeResultType.Failure))
                {
                    return Convert.ToInt32(PKIConstants.Microsoft.RequestDisposition.REVOKED);
                }
            }
            catch (Exception e)
            {
                throw new Exception($"Revoke failed with message {e.Message}");
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
            throw new NotImplementedException();
        }

        public override EnrollmentResult Enroll(ICertificateDataReader certificateDataReader, string csr,
            string subject, Dictionary<string, string[]> san, EnrollmentProductInfo productInfo,
            PKIConstants.X509.RequestFormat requestFormat, RequestUtilities.EnrollmentType enrollmentType)
        {
            try
            {
                InitiateInviteRequestType it = new InitiateInviteRequestType();
                
                var x = new XmlSerializer(it.GetType());
                byte[] bytes;
                using (MemoryStream stream = new MemoryStream())
                {
                    x.Serialize(stream, it);
                    bytes = stream.ToArray();
                }

                var signedRequest = _requestManager.BuildSignedCmsStructure("", "", bytes);

                switch (enrollmentType)
                {
                    case RequestUtilities.EnrollmentType.New:
                        var initiateResponse = Task.Run(async () =>
                            await QuovadisClient.InitiateInviteAsync(APIVersion.v2_0, ContentEncoding.UTF8,
                                signedRequest)).Result;

                        if (initiateResponse.InitiateInviteResponse.Result.Equals(ResultType.Success))
                        {
                            return new EnrollmentResult
                            {
                                Status = 9, //success
                                StatusMessage =
                                    $"Enrollment Succeeded with Id {initiateResponse.InitiateInviteResponse.TransactionId}"
                            };
                        }

                        break;
                    case RequestUtilities.EnrollmentType.Renew:
                        var renewResponse = Task.Run(async () =>
                            await QuovadisClient.RenewSSLCertAsync(APIVersion.v2_0, ContentEncoding.UTF8,
                                signedRequest)).Result;

                        if (renewResponse.RenewSSLCertResponse.Result.Equals(ResultType.Success) )
                        {
                            return new EnrollmentResult
                            {
                                Status = 9, //success
                                StatusMessage =
                                    $"Enrollment Succeeded with Id {renewResponse.RenewSSLCertResponse.TransactionId}"
                            };
                        }
                        break;
                    case RequestUtilities.EnrollmentType.Reissue:

                        break;
                }
            }
            catch (Exception e)
            {
                return new EnrollmentResult
                {
                    Status = 30, //failure
                    StatusMessage = $"Enrollment Failed with Message {e.Message}"
                };
            }

            return new EnrollmentResult
            {
                Status = 30, //failure
                StatusMessage = $"Enrollment Unknown Failure"
            };
        }


        
        public override CAConnectorCertificate GetSingleRecord(string caRequestId)
        {
            return new CAConnectorCertificate();
        }

        public override void Initialize(ICAConnectorConfigProvider configProvider)
        {
            BaseUrl = configProvider.CAConnectionData["BaseUrl"].ToString();
            //QuovadisClient = new CertificateServicesSoapClient(;

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