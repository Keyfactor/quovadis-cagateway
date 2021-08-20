﻿using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using CAProxy.AnyGateway;
using CAProxy.AnyGateway.Interfaces;
using CAProxy.AnyGateway.Models;
using CAProxy.Common;
using CSS.PKI;
using Keyfactor.AnyGateway.Quovadis.Client.Operations;
using Keyfactor.AnyGateway.Quovadis.Client.XSDs;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;
using CertificateStatusResultType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.CertificateStatusResultType;
using CertificateStatusType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.CertificateStatusType;
using InviteResultType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.InviteResultType;
using StatusResultType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.StatusResultType;
using StatusType = Keyfactor.AnyGateway.Quovadis.QuovadisClient.StatusType;
using CSS.Common.Logging;
using Keyfactor.AnyGateway.Quovadis.Models;

namespace Keyfactor.AnyGateway.Quovadis
{
    public class QuovadisCaProxy : BaseCAConnector
    {
        private string WebServiceSigningCertDir { get; set; }
        private string BaseUrl { get; set; }
        private string WebServiceSigningCertPassword { get; set; }

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

            try
            {
                var certs = new BlockingCollection<GatewayItem>(100);
                Gateway gw=new Gateway();
                _ = gw.GetCertificateList(certs, cancelToken, certificateDataReader);

                foreach (var currentResponseItem in certs.GetConsumingEnumerable(cancelToken))
                {
                    if (cancelToken.IsCancellationRequested)
                    {
                        Logger.Error("Synchronize was canceled.");
                        break;
                    }

                    try
                    {
                        Logger.Trace($"Took Certificate ID {currentResponseItem?.Id} from Queue");


                        if (currentResponseItem?.RequestType == "SSLRequest")
                        {
                            var certStatus =
                                new QuovadisCertificate<RequestSSLCertStatusRequestType, RequestSSLCertStatusResponse1>(BaseUrl,
                                    WebServiceSigningCertDir, WebServiceSigningCertPassword);
                            var certResponse = certStatus.RequestCertificate(currentResponseItem.SubscriberEmail,
                                currentResponseItem.Account, currentResponseItem.CaRequestId);
                            if (certResponse.RequestSSLCertStatusResponse.Status ==
                                StatusType.Valid |
                                certResponse.RequestSSLCertStatusResponse.Status == StatusType.Revoked &&
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
                                var _ = new X509Certificate2(Encoding.ASCII.GetBytes(certString));

                                blockingBuffer.Add(new CAConnectorCertificate
                                {
                                    CARequestID = $"{currentResponseItem.CaRequestId}",
                                    Certificate = certString,
                                    SubmissionDate = currentResponseItem.SubmissionDate,
                                    Status = Utilities.MapKeyfactorSslStatus(certResponse.RequestSSLCertStatusResponse
                                        .Status),
                                    ProductID = currentResponseItem.TemplateName
                                }, cancelToken);

                            }
                        }
                        else
                        {
                            var certStatus =
                                new QuovadisCertificate<RequestCertificateStatusRequestType, RequestCertificateStatusResponse1>(
                                    BaseUrl,
                                    WebServiceSigningCertDir, WebServiceSigningCertPassword);
                            var certResponse = certStatus.RequestCertificate(currentResponseItem?.SubscriberEmail,
                                currentResponseItem?.Account, currentResponseItem?.CaRequestId);
                            if (certResponse.RequestCertificateStatusResponse.Status ==
                                CertificateStatusType.Valid &&
                                certResponse.RequestCertificateStatusResponse.Result ==
                                CertificateStatusResultType.Success)
                            {
                                var certResult =
                                    new QuovadisCertificate<RetrieveCertificateRequestType, RetrieveCertificateResponse1>(BaseUrl,
                                        WebServiceSigningCertDir, WebServiceSigningCertPassword);
                                var cert = certResult.RequestCertificate(currentResponseItem?.SubscriberEmail,
                                    currentResponseItem?.Account, currentResponseItem?.CaRequestId);
                                var certString = cert.RetrieveCertificateResponse.Certificate;
                                var _ = new X509Certificate2(Encoding.ASCII.GetBytes(certString));

                                blockingBuffer.Add(new CAConnectorCertificate
                                {
                                    CARequestID = $"{currentResponseItem?.CaRequestId}",
                                    Certificate = certString,
                                    SubmissionDate = currentResponseItem?.SubmissionDate,
                                    Status = Utilities.MapKeyfactorCertStatus(certResponse.RequestCertificateStatusResponse
                                        .Status),
                                    ProductID = currentResponseItem?.TemplateName
                                }, cancelToken);
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
                                    var enrollment = new Enrollment<RequestSSLCertRequestType, RequestSSLCertResponse1>(BaseUrl,
                                        WebServiceSigningCertDir, WebServiceSigningCertPassword);
                                    var result = enrollment.PerformEnrollment(tempXml, csr, productInfo);

                                    if (result.RequestSSLCertResponse.Result == QuovadisClient.ResultType.Success)
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