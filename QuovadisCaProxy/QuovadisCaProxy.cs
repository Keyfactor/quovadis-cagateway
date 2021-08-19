using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using CAProxy.AnyGateway;
using CAProxy.AnyGateway.Interfaces;
using CAProxy.AnyGateway.Models;
using CAProxy.Common;
using CSS.PKI;
using System.Xml.Serialization;
using Keyfactor.AnyGateway.Quovadis.Client.Operations;
using Keyfactor.AnyGateway.Quovadis.Client.XSDs;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;
using CertificateStatusResultType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.CertificateStatusResultType;
using CertificateStatusType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.CertificateStatusType;
using InviteResultType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.InviteResultType;
using StatusResultType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.StatusResultType;
using StatusType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.StatusType;
using System.Data.SqlClient;

namespace Keyfactor.AnyGateway.Quovadis
{
    public class QuovadisCaProxy : BaseCAConnector
    {
        private readonly RequestManager requestManager;

        public QuovadisCaProxy()
        {
            requestManager = new RequestManager();
        }

        private CertificateServicesSoapClient QuovadisClient { get; set; }
        private string WebServiceSigningCertDir { get; set; }
        private string BaseUrl { get; set; }
        private string WebServiceSigningCertPassword { get; set; }
        private ICAConnectorConfigProvider Config { get; set; }

        public override int Revoke(string caRequestId, string hexSerialNumber, uint revocationReason)
        {
           /* try
            {
                /var paramArray = input.Split(':')[1];
                var valArray = paramArray.Split(',');
                var transactionId = valArray[0];
                var emailAddress = valArray[1];
                var account = valArray[2];
                var enrollType = valArray[3];
                var revokeReason = valArray[4];

                var actualCert = GetX509Certificate(enrollType, emailAddress, account, transactionId);
                if (actualCert != null)
                {
                    var revoke = new Revocation(BaseUrl, WebServiceSigningCertDir, WebServiceSigningCertPassword);
                    //perform the revoke
                    Console.Write(revoke.RevokeCertificate(actualCert, account, revokeReason));
                }
            }
            catch (Exception e)
            {
                throw new Exception($"Revoke failed with message {e.Message}");
            }
            
            throw new Exception("Revoke failed");
            */

           return 0;
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
            Logger.Debug($"Entering Synchronization process");

            Logger.Trace($"Full Sync? {certificateAuthoritySyncInfo.DoFullSync}");
            Logger.MethodEntry(ILogExtensions.MethodLogLevel.Debug);
            try
            {
                var certs = new BlockingCollection<ICertificateResponse>(100);
                CscGlobalClient.SubmitCertificateListRequestAsync(certs, cancelToken);

                foreach (var currentResponseItem in certs.GetConsumingEnumerable(cancelToken))
                {
                    if (cancelToken.IsCancellationRequested)
                    {
                        Logger.Error("Synchronize was canceled.");
                        break;
                    }

                    try
                    {
                        Logger.Trace($"Took Certificate ID {currentResponseItem?.Uuid} from Queue");
                        var certStatus = _requestManager.MapReturnStatus(currentResponseItem?.Status);

                        //Keyfactor sync only seems to work when there is a valid cert and I can only get Active valid certs from Csc Global
                        if (certStatus == Convert.ToInt32(PKIConstants.Microsoft.RequestDisposition.ISSUED) ||
                            certStatus == Convert.ToInt32(PKIConstants.Microsoft.RequestDisposition.REVOKED))
                        {
                            //One click renewal/reissue won't work for this implementation so there is an option to disable it by not syncing back template
                            var productId = "CscGlobal";
                            if (EnableTemplateSync) productId = currentResponseItem?.CertificateType;

                            var fileContent =
                                Encoding.ASCII.GetString(
                                    Convert.FromBase64String(currentResponseItem?.Certificate ?? string.Empty));
                            var fileContent2 =
                                Encoding.UTF8.GetString(
                                    Convert.FromBase64String(fileContent)); //Double base64 Encoded for some reason

                            Logger.Trace($"Certificate Content: {fileContent2}");

                            if (fileContent2.Length > 0)
                            {
                                var certData = fileContent2.Replace("\r\n", string.Empty);
                                var splitCerts =
                                    certData.Split(new[] { "-----END CERTIFICATE-----", "-----BEGIN CERTIFICATE-----" },
                                        StringSplitOptions.RemoveEmptyEntries);
                                foreach (var cert in splitCerts)
                                    if (!cert.Contains(".crt"))
                                    {
                                        Logger.Trace($"Split Cert Value: {cert}");

                                        var currentCert = new X509Certificate2(Encoding.ASCII.GetBytes(cert));
                                        if (!currentCert.Subject.Contains("AAA Certificate Services") &&
                                            !currentCert.Subject.Contains("USERTrust RSA Certification Authority") &&
                                            !currentCert.Subject.Contains("Trusted Secure Certificate Authority 5") &&
                                            !currentCert.Subject.Contains("AddTrust External CA Root") &&
                                            !currentCert.Subject.Contains("Trusted Secure Certificate Authority DV"))
                                            blockingBuffer.Add(new CAConnectorCertificate
                                            {
                                                CARequestID = $"{currentResponseItem?.Uuid}-{currentCert.SerialNumber}",
                                                Certificate = cert,
                                                SubmissionDate = currentResponseItem?.OrderDate == null
                                                    ? Convert.ToDateTime(currentCert.NotBefore)
                                                    : Convert.ToDateTime(currentResponseItem.OrderDate),
                                                Status = certStatus,
                                                ProductID = productId
                                            }, cancelToken);
                                    }
                            }
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        Logger.Error("Synchronize was canceled.");
                        break;
                    }
                }
            }
            catch (AggregateException aggEx)
            {
                Logger.Error("Csc Global Synchronize Task failed!");
                Logger.MethodExit(ILogExtensions.MethodLogLevel.Debug);
                // ReSharper disable once PossibleIntendedRethrow
                throw aggEx;
            }

            Logger.MethodExit(ILogExtensions.MethodLogLevel.Debug);


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

                switch (enrollmentType)
                {
                    case RequestUtilities.EnrollmentType.New:
                        try
                        {
                            var templateId = productInfo.ProductID;
                            Logger.Trace($"Entering New Enrollment with ProductId {templateId}");

                            if (templateId != null)
                            {
                                var enrollType = productInfo.ProductParameters["EnrollmentType"];
                                var tempXml = productInfo.ProductParameters["EnrollmentTemplate"];
                                Logger.Trace($"Enroll Type {enrollType}");
                                Logger.Trace($"Temp XML Retrieved {tempXml}");

                                if (enrollType == "SSLRequest")
                                {
                                    var enrollment = new Enrollment<RequestSSLCertRequestType, RequestSSLCertResponse1>(BaseUrl,
                                        WebServiceSigningCertDir, WebServiceSigningCertPassword);
                                    var result = enrollment.PerformEnrollment(tempXml, csr, productInfo);

                                    if (result.RequestSSLCertResponse.Result == Quovadis.QuovadisClient.ResultType.Success)
                                    {
                                        return new EnrollmentResult
                                        {
                                            Status = (int)PKIConstants.Microsoft.RequestDisposition.EXTERNAL_VALIDATION, //will never be instant has to be approved
                                            CARequestID = result.RequestSSLCertResponse.TransactionId,
                                            StatusMessage = $"Enrollment Succeeded with Id {result.RequestSSLCertResponse.Details}",
                                        };
                                    }
                                    return new EnrollmentResult
                                    {
                                        Status = (int)PKIConstants.Microsoft.RequestDisposition.FAILED, //will never be instant has to be approved
                                        StatusMessage = $"SSL Cert Enrollment Failed with message {result.RequestSSLCertResponse.Details}"
                                    };
                                }

                                if (enrollType == "InitiateInviteRequest")
                                {
                                    var enrollment = new Enrollment<InitiateInviteRequestType, InitiateInviteResponse1>(BaseUrl,
                                        WebServiceSigningCertDir, WebServiceSigningCertPassword);
                                    var result = enrollment.PerformEnrollment(tempXml, csr, productInfo);

                                    if (result.InitiateInviteResponse.Result == InviteResultType.Success)
                                    {
                                        return new EnrollmentResult
                                        {
                                            Status = (int)PKIConstants.Microsoft.RequestDisposition.EXTERNAL_VALIDATION, //will never be instant has to be approved
                                            CARequestID = result.InitiateInviteResponse.TransactionId,
                                            StatusMessage = $"Enrollment Succeeded with Id {result.InitiateInviteResponse.Details}"
                                        };
                                    }

                                    return new EnrollmentResult
                                    {
                                        Status = (int)PKIConstants.Microsoft.RequestDisposition.FAILED, //will never be instant has to be approved
                                        StatusMessage = $"Cert Enrollment Failed with message {result.InitiateInviteResponse.Details}"
                                    };

                                }
                            }
                        }
                        catch (Exception e)
                        {
                            Logger.Error($"Error Occurred in New Enrollment {e.Message}");
                            throw;
                        }
                        break;
                    case RequestUtilities.EnrollmentType.Renew:
                        /*
                        var transactionId = certificateDataReader.GetCertificateRecord();

                        var tempRenewXml = productInfo.ProductParameters["EnrollmentTemplate"];
                        var renewal = new Renewal(BaseUrl, WebServiceSigningCertDir, WebServiceSigningCertPassword);
                        var renewResponse=renewal.RenewCertificate(tempRenewXml, csr, productInfo, transactionId);
                        */
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
            return new CAConnectorCertificate() 
            { 
                CARequestID=caRequestId
            };
        }

        public override void Initialize(ICAConnectorConfigProvider configProvider)
        {
            BaseUrl = configProvider.CAConnectionData["BaseUrl"].ToString();
            WebServiceSigningCertDir= configProvider.CAConnectionData["WebServiceSigningCertDir"].ToString();
            WebServiceSigningCertPassword = configProvider.CAConnectionData["WebServiceSigningCertPassword"].ToString();
            Config = configProvider;
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

        private X509Certificate2 GetX509Certificate(string enrollType, string emailAddress, string account,
        string transactionId)
        {
            X509Certificate2 actualCert = null;

            if (enrollType == "SSL")
            {
                var certStatus =
                    new QuovadisCertificate<RequestSSLCertStatusRequestType, RequestSSLCertStatusResponse1>(BaseUrl,
                        WebServiceSigningCertDir, WebServiceSigningCertPassword);
                var certResponse = certStatus.RequestCertificate(emailAddress, account, transactionId);
                if (certResponse.RequestSSLCertStatusResponse.Status ==
                    StatusType.Valid &&
                    certResponse.RequestSSLCertStatusResponse.Result ==
                    StatusResultType.Success)
                {
                    var certResult =
                        new QuovadisCertificate<RetrieveSSLCertRequestType, RetrieveSSLCertResponse1>(BaseUrl,
                            WebServiceSigningCertDir, WebServiceSigningCertPassword);
                    var cert = certResult.RequestCertificate(emailAddress, account, transactionId);
                    var certString = cert.RetrieveSSLCertResponse.Certificate;
                    actualCert = new X509Certificate2(Encoding.ASCII.GetBytes(certString));
                }
            }
            else
            {
                var certStatus =
                    new QuovadisCertificate<RequestCertificateStatusRequestType, RequestCertificateStatusResponse1>(
                        BaseUrl,
                        WebServiceSigningCertDir, WebServiceSigningCertPassword);
                var certResponse = certStatus.RequestCertificate(emailAddress, account, transactionId);
                if (certResponse.RequestCertificateStatusResponse.Status ==
                    CertificateStatusType.Valid &&
                    certResponse.RequestCertificateStatusResponse.Result ==
                    CertificateStatusResultType.Success)
                {
                    var certResult =
                        new QuovadisCertificate<RetrieveCertificateRequestType, RetrieveCertificateResponse1>(BaseUrl,
                            WebServiceSigningCertDir, WebServiceSigningCertPassword);
                    var cert = certResult.RequestCertificate(emailAddress, account, transactionId);
                    var certString = cert.RetrieveCertificateResponse.Certificate;
                    actualCert = new X509Certificate2(Encoding.ASCII.GetBytes(certString));
                }
            }

            return actualCert;
        }
    }
}