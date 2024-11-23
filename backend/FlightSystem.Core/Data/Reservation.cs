using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class Reservation
    {
        public decimal Id { get; set; }
        public DateTime? Reservationdate { get; set; }
        public decimal? Totalprice { get; set; }
        public decimal? Numofpassengers { get; set; }
        public decimal? Userid { get; set; }
        public decimal? Flightid { get; set; }

        public virtual Flight? Flight { get; set; }
        public virtual User? User { get; set; }
    }
}
