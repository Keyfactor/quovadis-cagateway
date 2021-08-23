using System;
using Keyfactor.AnyGateway.Quovadis.Interfaces;

namespace Keyfactor.AnyGateway.Quovadis.Models
{
    public class GatewayItem:IGatewayItem
    {
        public int Id { get; set; }
        public int Status { get; set; }
        public string CaRequestId { get; set; }
        public DateTime SubmissionDate { get; set; }
        public string RequestCn { get; set; }
        public string RequestSubject { get; set; }
        public string RequestType {get; set;}
        public string SubscriberEmail { get; set; }
        public string Account { get; set; }
        public string TemplateName { get; set; }
        public string Sync { get; set;}


    }
}
