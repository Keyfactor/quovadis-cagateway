using System;

namespace Keyfactor.AnyGateway.Quovadis.Interfaces
{
    public interface IGatewayItem
    {
        int Id { get; set; }
        int Status { get; set; }
        string CaRequestId { get; set; }
        DateTime SubmissionDate { get; set; }
        string RequestCn { get; set; }
        string RequestSubject { get; set; }
        string RequestType { get; set; }
        string SubscriberEmail { get; set; }
        string Account { get; set; }
        string TemplateName { get; set; }
        string Sync { get; set; }
    }
}