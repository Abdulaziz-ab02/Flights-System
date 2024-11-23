using System;
using System.Collections.Generic;
using System.Linq;  
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.DTO
{
    public class SearchReservationDTO
    {
        public decimal Id { get; set; }
        public DateTime? Reservationdate { get; set; }
        public decimal? Totalprice { get; set; }
        public decimal? Numofpassengers { get; set; }

        public string? Firstname { get; set; }
        public string? Lastname { get; set; }

        public string? Flightnumber { get; set; }
        public DateTime? Departuredate { get; set; }
        public DateTime? Destinationdate { get; set; }


        public DateTime? DateFrom { get; set; }
        public DateTime? DateTo { get; set; }

    }
}
