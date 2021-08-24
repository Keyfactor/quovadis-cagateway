using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CAProxy.AnyGateway;
using CAProxy.AnyGateway.Interfaces;
using CAProxy.AnyGateway.Models;
using CAProxy.Common;
using CSS.Common;
using CSS.Common.Logging;
using CSS.PKI;
using Keyfactor.AnyGateway.Quovadis.Client;
using Keyfactor.AnyGateway.Quovadis.Client.Operations;
using Keyfactor.AnyGateway.Quovadis.Client.XSDs;
using Keyfactor.AnyGateway.Quovadis.Models;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;
using CertificateStatusResultType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.CertificateStatusResultType;
using CertificateStatusType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.CertificateStatusType;
using InviteResultType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.InviteResultType;
using ResultType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.ResultType;
using RevokeCertificateBySerialNoResultType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.RevokeCertificateBySerialNoResultType;
using StatusResultType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.StatusResultType;
using StatusType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.StatusType;

namespace Keyfactor.AnyGateway.Quovadis
{
    public class QuovadisCaProxy : BaseCAConnector
    {
        private string WebServiceSigningCertDir { get; set; }
        private string BaseUrl { get; set; }
        private string WebServiceSigningCertPassword { get; set; }
        private string Organization { get; set; }
        private ICAConnectorConfigProvider ConfigSettings { get; set; }

        public override int Revoke(string caRequestId, string hexSerialNumber, uint revocationReason)
        {
            KeyfactorClient kfClient=new KeyfactorClient(ConfigSettings);
            var keyfactorCert =
                Task.Run(async () =>
                        await kfClient.SubmitGetKeyfactorCertAsync(hexSerialNumber))
                    .Result;

            Revocation revoke = new Revocation(BaseUrl,WebServiceSigningCertDir,WebServiceSigningCertPassword);
            var revokeResult =
                revoke.RevokeCertificate(hexSerialNumber, keyfactorCert[0].IssuerDn, Organization, Convert.ToInt16(revocationReason));

            if (revokeResult.RevokeCertificateBySerialNoResponse.Result == RevokeCertificateBySerialNoResultType.Failure)
            {
                return -1;
            }

            return Convert.ToInt32(PKIConstants.Microsoft.RequestDisposition.REVOKED);

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
            Logger.Debug("Entering Synchronization process");
            Logger.Trace($"Full Sync? {certificateAuthoritySyncInfo.DoFullSync}");

            try
            {
                var certs = new BlockingCollection<GatewayItem>(100);
                var gw = new Gateway();
                _ = gw.GetCertificateList(certs, cancelToken, certificateDataReader, Organization, ConfigSettings);

                foreach (var currentResponseItem in certs.GetConsumingEnumerable(cancelToken))
                    //Quovadis only allows so many download attempts so if it is there don't download again
                    if (currentResponseItem.Status != 20 && currentResponseItem.Sync == "Sync")
                    {
                        if (cancelToken.IsCancellationRequested)
                        {
                            Logger.Error("Synchronize was canceled.");
                            break;
                        }

                        try
                        {
                            Logger.Trace($"Took Certificate ID {currentResponseItem.Id} from Queue");

                            if (currentResponseItem.RequestType == "SSLRequest")
                            {
                                var certStatus =
                                    new QuovadisCertificate<RequestSSLCertStatusRequestType,
                                        RequestSSLCertStatusResponse1>(BaseUrl,
                                        WebServiceSigningCertDir, WebServiceSigningCertPassword);
                                var certResponse = certStatus.RequestCertificate(currentResponseItem.SubscriberEmail,
                                    currentResponseItem.Account, currentResponseItem.CaRequestId);
                                if ((certResponse.RequestSSLCertStatusResponse.Status ==
                                     StatusType.Valid) |
                                    (certResponse.RequestSSLCertStatusResponse.Status == StatusType.Revoked) &&
                                    certResponse.RequestSSLCertStatusResponse.Result ==
                                    StatusResultType.Success)
                                {
                                    var certResult =
                                        new QuovadisCertificate<RetrieveSSLCertRequestType, RetrieveSSLCertResponse1>(
                                            BaseUrl,
                                            WebServiceSigningCertDir, WebServiceSigningCertPassword);
                                    var cert = certResult.RequestCertificate(currentResponseItem.SubscriberEmail,
                                        currentResponseItem.Account, currentResponseItem.CaRequestId);
                                    var certString = cert.RetrieveSSLCertResponse.Certificate;
                                    //Quovadis only allows so many downloads of the cert, 110 is the error you get after you reached the max
                                    if (cert.RetrieveSSLCertResponse.ErrorCode != "110")
                                    {
                                        var _ = new X509Certificate2(Encoding.ASCII.GetBytes(certString));

                                        blockingBuffer.Add(new CAConnectorCertificate
                                        {
                                            CARequestID = $"{currentResponseItem.CaRequestId}",
                                            Certificate = certString,
                                            SubmissionDate = currentResponseItem.SubmissionDate,
                                            Status = Utilities.MapKeyfactorSslStatus(certResponse
                                                .RequestSSLCertStatusResponse
                                                .Status),
                                            ProductID = currentResponseItem.TemplateName
                                        }, cancelToken);
                                    }
                                }
                            }
                            else
                            {
                                var certStatus =
                                    new QuovadisCertificate<RequestCertificateStatusRequestType,
                                        RequestCertificateStatusResponse1>(
                                        BaseUrl,
                                        WebServiceSigningCertDir, WebServiceSigningCertPassword);
                                var certResponse = certStatus.RequestCertificate(currentResponseItem.SubscriberEmail,
                                    currentResponseItem.Account, currentResponseItem.CaRequestId);
                                if (certResponse.RequestCertificateStatusResponse.Status ==
                                    CertificateStatusType.Valid &&
                                    certResponse.RequestCertificateStatusResponse.Result ==
                                    CertificateStatusResultType.Success)
                                {
                                    var certResult =
                                        new QuovadisCertificate<RetrieveCertificateRequestType,
                                            RetrieveCertificateResponse1>(BaseUrl,
                                            WebServiceSigningCertDir, WebServiceSigningCertPassword);
                                    var cert = certResult.RequestCertificate(currentResponseItem.SubscriberEmail,
                                        currentResponseItem.Account, currentResponseItem.CaRequestId);
                                    var certString = cert.RetrieveCertificateResponse.Certificate;
                                    //Quovadis only allows so many downloads of the cert, 110 is the error you get after you reached the max
                                    if (cert.RetrieveCertificateResponse.ErrorCode != "110")
                                    {
                                        var _ = new X509Certificate2(Encoding.ASCII.GetBytes(certString));

                                        blockingBuffer.Add(new CAConnectorCertificate
                                        {
                                            CARequestID = $"{currentResponseItem.CaRequestId}",
                                            Certificate = certString,
                                            SubmissionDate = currentResponseItem.SubmissionDate,
                                            Status = Utilities.MapKeyfactorCertStatus(certResponse
                                                .RequestCertificateStatusResponse
                                                .Status),
                                            ProductID = currentResponseItem.TemplateName
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
                                    var enrollment = new Enrollment<RequestSSLCertRequestType, RequestSSLCertResponse1>(
                                        BaseUrl,
                                        WebServiceSigningCertDir, WebServiceSigningCertPassword);
                                    var result = enrollment.PerformEnrollment(tempXml, csr, productInfo);

                                    if (result.RequestSSLCertResponse.Result == ResultType.Success)
                                        return new EnrollmentResult
                                        {
                                            Status =
                                                (int) PKIConstants.Microsoft.RequestDisposition
                                                    .EXTERNAL_VALIDATION, //will never be instant has to be approved
                                            CARequestID = result.RequestSSLCertResponse.TransactionId,
                                            StatusMessage =
                                                $"Enrollment Succeeded with Id {result.RequestSSLCertResponse.Details}"
                                        };
                                    return new EnrollmentResult
                                    {
                                        Status = (int) PKIConstants.Microsoft.RequestDisposition
                                            .FAILED, //will never be instant has to be approved
                                        StatusMessage =
                                            $"SSL Cert Enrollment Failed with message {result.RequestSSLCertResponse.Details}"
                                    };
                                }

                                if (enrollType == "InitiateInviteRequest")
                                {
                                    var enrollment = new Enrollment<InitiateInviteRequestType, InitiateInviteResponse1>(
                                        BaseUrl,
                                        WebServiceSigningCertDir, WebServiceSigningCertPassword);
                                    var result = enrollment.PerformEnrollment(tempXml, csr, productInfo);

                                    if (result.InitiateInviteResponse.Result == InviteResultType.Success)
                                        return new EnrollmentResult
                                        {
                                            Status =
                                                (int) PKIConstants.Microsoft.RequestDisposition
                                                    .EXTERNAL_VALIDATION, //will never be instant has to be approved
                                            CARequestID = result.InitiateInviteResponse.TransactionId,
                                            StatusMessage =
                                                $"Enrollment Succeeded with Id {result.InitiateInviteResponse.Details}"
                                        };

                                    return new EnrollmentResult
                                    {
                                        Status = (int) PKIConstants.Microsoft.RequestDisposition
                                            .FAILED, //will never be instant has to be approved
                                        StatusMessage =
                                            $"Cert Enrollment Failed with message {result.InitiateInviteResponse.Details}"
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
                    case RequestUtilities.EnrollmentType.Reissue:
                    case RequestUtilities.EnrollmentType.Renew:
                        //One click won't work for this implementation b/c we are missing enrollment params
                        if (productInfo.ProductParameters.ContainsKey("Enrollment Type"))
                        {
                            var priorCert = certificateDataReader.GetCertificateRecord(
                                DataConversion.HexToBytes(productInfo.ProductParameters["PriorCertSN"]));
                            var uUId = priorCert.CARequestID; //uUId is a GUID
                            Logger.Trace($"Reissue CA RequestId: {uUId}");
                            var ren = new Renewal(BaseUrl, WebServiceSigningCertDir, WebServiceSigningCertPassword);
                            var renResult = ren.RenewCertificate(productInfo.ProductParameters["EnrollmentTemplate"],
                                csr, productInfo, uUId);
                            if (renResult.RenewSSLCertResponse.Result == ResultType.Success)
                                return new EnrollmentResult
                                {
                                    Status = (int) PKIConstants.Microsoft.RequestDisposition
                                        .EXTERNAL_VALIDATION, //will never be instant has to be approved
                                    CARequestID = renResult.RenewSSLCertResponse.TransactionId,
                                    StatusMessage =
                                        $"Re-Issue Succeeded with Id {renResult.RenewSSLCertResponse.Details}"
                                };
                            return new EnrollmentResult
                            {
                                Status = (int) PKIConstants.Microsoft.RequestDisposition
                                    .FAILED, //will never be instant has to be approved
                                StatusMessage = $"Re-Issue Failed with message {renResult.RenewSSLCertResponse.Details}"
                            };
                        }
                        else
                        {
                            return new EnrollmentResult
                            {
                                Status = 30, //failure
                                StatusMessage =
                                    "One click Renew Is Not Available for this Certificate Type.  Use the configure button instead."
                            };
                        }
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
                StatusMessage = "Enrollment Unknown Failure"
            };
        }


        public override CAConnectorCertificate GetSingleRecord(string caRequestId)
        {
            return new CAConnectorCertificate
            {
                CARequestID = caRequestId
            };
        }

        public override void Initialize(ICAConnectorConfigProvider configProvider)
        {
            BaseUrl = configProvider.CAConnectionData["BaseUrl"].ToString();
            WebServiceSigningCertDir = configProvider.CAConnectionData["WebServiceSigningCertDir"].ToString();
            WebServiceSigningCertPassword = configProvider.CAConnectionData["WebServiceSigningCertPassword"].ToString();
            Organization = configProvider.CAConnectionData["OrganizationId"].ToString();
            ConfigSettings = configProvider;
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