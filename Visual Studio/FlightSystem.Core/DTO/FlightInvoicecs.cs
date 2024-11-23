using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.DTO
{
    public class FlightInvoicecs
    {
        public string FlightNumber { get; set; }
        public string Departure { get; set; }
        public string Arrival { get; set; }
        public string Date { get; set; }
        public string PassengerName { get; set; }
        public string RecipientEmail { get; set; } // Email to which the PDF will be sent

    }
}
