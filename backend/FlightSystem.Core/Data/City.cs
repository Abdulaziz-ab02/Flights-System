using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class City
    {
        public City()
        {
            Airports = new HashSet<Airport>();
        }

        public decimal Id { get; set; }
        public string? Cityname { get; set; }
        public string? Cityimage { get; set; }
        public decimal? Countryid { get; set; }

        public virtual Country? Country { get; set; }
        public virtual ICollection<Airport> Airports { get; set; }
    }
}
