using System;

namespace Keyfactor.AnyGateway.Quovadis.Exceptions
{
    public class RetryCountExceededException : Exception
    {
        public RetryCountExceededException(string message) : base(message)
        {
        }
    }
}