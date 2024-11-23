using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class Degree
    {
        public Degree()
        {
            DegreeFacilities = new HashSet<DegreeFacility>();
            Flights = new HashSet<Flight>();
        }

        public decimal Id { get; set; }
        public string? Degreename { get; set; }

        public virtual ICollection<DegreeFacility> DegreeFacilities { get; set; }
        public virtual ICollection<Flight> Flights { get; set; }
    }
}
