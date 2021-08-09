using System;
using System.IO;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Threading.Tasks;
using System.Xml.Serialization;
using Keyfactor.AnyGateway.Quovadis.QuovadisClient;

namespace QuovadisAPITester
{
    public class QuovadisCertificate<T, TR>
    {
        private readonly string baseUrl;
        private readonly string wsSigningCertDir;
        private readonly string wsSigningCertPwd;

        public QuovadisCertificate(string baseUrl, string wsSigningCertDir, string wsSigningCertPwd)
        {
            this.baseUrl = baseUrl;
            this.wsSigningCertDir = wsSigningCertDir;
            this.wsSigningCertPwd = wsSigningCertPwd;
        }

        public TR RequestCertificate(string emailAddress, string account, string transactionId)
        {

            var req = BuildRequest(emailAddress, account, transactionId);

            var x = new XmlSerializer(req.GetType());
            byte[] bytes;
            using (MemoryStream stream = new MemoryStream())
            {
                x.Serialize(stream, req);
                bytes = stream.ToArray();
            }

            Binding bind = new BasicHttpsBinding();
            EndpointAddress ep = new EndpointAddress(baseUrl);
            var quovadisClient = new CertificateServicesSoapClient(bind, ep);

            var signedRequest = Utilities.BuildSignedCmsStructure(wsSigningCertDir, wsSigningCertPwd, bytes);

            if (typeof(T).Name == "RequestCertificateStatusRequest")
            {
                var response = Task.Run(async () =>
                    await quovadisClient.RequestCertificateStatusAsync(APIVersion.v1_0, ContentEncoding.UTF8,
                        signedRequest)).Result;
                return (TR)Convert.ChangeType(response, typeof(TR));
            }
            else if (typeof(T).Name == "RequestSSLCertStatusRequestType")
            {
                var response = Task.Run(async () =>
                    await quovadisClient.RequestSSLCertStatusAsync(APIVersion.v1_0, ContentEncoding.UTF8,
                        signedRequest)).Result;
                return (TR)Convert.ChangeType(response, typeof(TR));
            }
            else if (typeof(T).Name == "RetrieveCertificateRequest")
            {
                var response = Task.Run(async () =>
                    await quovadisClient.RetrieveCertificateAsync(APIVersion.v1_0, ContentEncoding.UTF8,
                        signedRequest)).Result;
                return (TR)Convert.ChangeType(response, typeof(TR));
            }
            else
            {
                var response = Task.Run(async () =>
                    await quovadisClient.RetrieveSSLCertAsync(APIVersion.v1_0, ContentEncoding.UTF8,
                        signedRequest)).Result;
                return (TR)Convert.ChangeType(response, typeof(TR));
            }


        }

        private T BuildRequest(string emailAddress, string account, string transactionId)
        {
            var type = typeof(T);
            if (type.Name == "RequestCertificateStatusRequestType")
            {
                CertificateStatusAccountInfo a = new CertificateStatusAccountInfo
                {
                    Name = account, Organisation = account
                };

                RequestCertificateStatusRequestType req = new RequestCertificateStatusRequestType
                {
                    Account = a,
                    TransactionId = transactionId,
                    RequestPartyEmailAddress = emailAddress,
                    DateTime = DateTime.Now
                };
                return (T) Convert.ChangeType(req, typeof(T));
            }
            else if(type.Name == "RequestSSLCertStatusRequestType")
            {
                StatusAccountInfo a = new StatusAccountInfo
                {
                    Name = account,
                    Organisation = account
                };

                RequestSSLCertStatusRequestType req = new RequestSSLCertStatusRequestType
                {
                    Account = a,
                    TransactionId = transactionId,
                    SubscriberEmailAddress = emailAddress,
                    DateTime = DateTime.Now
                };
                return (T)Convert.ChangeType(req, typeof(T));
            }
            else if (type.Name == "RetrieveCertificateRequestType")
            {
                RetrieveCertificateAccountInfo a = new RetrieveCertificateAccountInfo
                {
                    Name = account,
                    Organisation = account
                };
                RetrieveCertificateRequestType req = new RetrieveCertificateRequestType
                {
                    Account = a,
                    TransactionId = transactionId,
                    RequestPartyEmailAddress = emailAddress,
                    DateTime = DateTime.Now
                };
                return (T)Convert.ChangeType(req, typeof(T));
            }
            else
            {
                RetrieveAccountInfo a = new RetrieveAccountInfo
                {
                    Name = account,
                    Organisation = account
                };
                RetrieveSSLCertRequestType req = new RetrieveSSLCertRequestType
                {
                    Account = a,
                    TransactionId = transactionId,
                    SubscriberEmailAddress = emailAddress,
                    DateTime = DateTime.Now
                };
                return (T)Convert.ChangeType(req, typeof(T));
            }
        }
    }
}
