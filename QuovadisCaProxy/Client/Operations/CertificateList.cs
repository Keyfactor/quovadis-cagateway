using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Keyfactor.AnyGateway.Quovadis.Client.Operations
{
    public class CertificateList
    {

        public void GetCertificateList()
        {
            var gatewayConnectionString = Utilities.GetGatewayConnection(certificateDataReader);

            using (SqlConnection connection = new SqlConnection(gatewayConnectionString))
            {
                using (SqlCommand command = new SqlCommand("SELECT c.Id,c.Status,c.CARequestID,c.SubmissionDate,c.RequestCN,c.RequestSubject,r.AttributeKey,r.AttributeValue FROM Certificates c JOIN RequestAttributes r on r.CertificateId = c.Id Where CARequestID is not null and AttributeKey = 'Enrollment Type'", connection))
                {
                    connection.Open();
                    var rdr = command.ExecuteReaderAsync();
                    var response = Task.Run(async () => await command.ExecuteReaderAsync()).Result;


                }
            }
        }

    }
}
