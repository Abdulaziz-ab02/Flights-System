using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class Flight
    {
        public Flight()
        {
            Reservations = new HashSet<Reservation>();
        }

        public decimal Id { get; set; }
        public string? Flightnumber { get; set; }
        public decimal? Capacity { get; set; }
        public decimal? Priceperpassenger { get; set; }
        public DateTime? Departuredate { get; set; }
        public DateTime? Destinationdate { get; set; }
        public string? Status { get; set; }
        public decimal? Discountvalue { get; set; }
        public decimal? Airlineid { get; set; }
        public decimal? Departureairportid { get; set; }
        public decimal? Destinationairportid { get; set; }
        public decimal? Degreeid { get; set; }
        public decimal? PriceAfterDiscount { get; set; }


        public virtual Airline? Airline { get; set; }
        public virtual Degree? Degree { get; set; }
        public virtual Airport? Departureairport { get; set; }
        public virtual Airport? Destinationairport { get; set; }
        public virtual ICollection<Reservation> Reservations { get; set; }
    }
}
