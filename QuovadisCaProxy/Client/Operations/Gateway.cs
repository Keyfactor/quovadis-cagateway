using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Serialization;
using CAProxy.AnyGateway.Interfaces;
using CSS.Common.Logging;
using Keyfactor.AnyGateway.Quovadis.Exceptions;
using Keyfactor.AnyGateway.Quovadis.Models;

namespace Keyfactor.AnyGateway.Quovadis.Client.Operations
{
    public class Gateway : LoggingClientBase
    {
        public async Task GetCertificateList(BlockingCollection<GatewayItem> bc,
            CancellationToken ct, ICertificateDataReader certificateDataReader,string account, ICAConnectorConfigProvider configSettings)
        {
            Logger.MethodEntry(ILogExtensions.MethodLogLevel.Debug);
            try
            {
                var gatewayConnectionString = Utilities.GetGatewayConnection(certificateDataReader);
                


                using (var connection = new SqlConnection(gatewayConnectionString))
                {
                    using (var command = new SqlCommand(
                        "  select Id, Status,	CARequestId, SubmissionDate, RequestCN,	RequestSubject,  (select AttributeKey,AttributeValue from RequestAttributes r where r.CertificateId = c.Id for xml path('Attribute'), type) from (select distinct Id, Status,CARequestId,SubmissionDate,RequestCN,RequestSubject from Certificates where CARequestID is not null) c FOR XML PATH ('Certificate'), root ('Certificates')",
                        connection))
                    {
                        connection.Open();
                        using (var resp = command.ExecuteXmlReader())
                        {
                            XmlSerializer serializer = new XmlSerializer(typeof(List<Certificate>), new XmlRootAttribute("Certificates"));
                            List<Certificate> certList = (List<Certificate>)serializer.Deserialize(resp);
                          
                            if (certList.Count>0)
                                foreach (var cert in certList)
                                {
                                    var templateName = cert.Attribute
                                        .FirstOrDefault(c => c.AttributeKey == "CertificateTemplate")?.AttributeValue;
                                    var r = new GatewayItem
                                    {
                                        Id = cert.Id,
                                        SubscriberEmail = cert.Attribute.FirstOrDefault(c => c.AttributeKey== "Subscriber Email")?.AttributeValue ?? cert.Attribute.FirstOrDefault(c => c.AttributeKey == "Admin Email")?.AttributeValue,
                                        RequestType = cert.Attribute.FirstOrDefault(c => c.AttributeKey == "Enrollment Type")?.AttributeValue,
                                        Account = account,
                                        CaRequestId = cert.CaRequestId,
                                        RequestSubject = cert.RequestSubject,
                                        SubmissionDate=cert.SubmissionDate,
                                        RequestCn = cert.RequestCn,
                                        TemplateName = templateName,
                                        Sync= configSettings.CAConnectionData[templateName ?? string.Empty].ToString(),
                                        Status =cert.Status
                                    };

                                    if (bc.TryAdd(r, 10, ct))
                                        Logger.Trace($"Added Template ID {r.Id} to Queue for processing");
                                    else
                                        Logger.Trace($"Adding {r} blocked. Retry");
                                }
                        }
                    }
                }

                bc.CompleteAdding();
            }
            catch (OperationCanceledException cancelEx)
            {
                Logger.Warn($"Synchronize method was cancelled. Message: {cancelEx.Message}");
                bc.CompleteAdding();
                Logger.MethodExit(ILogExtensions.MethodLogLevel.Debug);
                // ReSharper disable once PossibleIntendedRethrow
                throw cancelEx;
            }

            catch (RetryCountExceededException retryEx)
            {
                Logger.Error($"Retries Failed: {retryEx.Message}");
                Logger.MethodExit(ILogExtensions.MethodLogLevel.Debug);
            }

            catch (HttpRequestException ex)
            {
                Logger.Error($"HttpRequest Failed: {ex.Message}");
                Logger.MethodExit(ILogExtensions.MethodLogLevel.Debug);
            }

            Logger.MethodExit(ILogExtensions.MethodLogLevel.Debug);
        }
    }
}