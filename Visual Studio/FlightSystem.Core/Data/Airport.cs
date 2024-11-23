using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class Airport
    {
        public Airport()
        {
            FlightDepartureairports = new HashSet<Flight>();
            FlightDestinationairports = new HashSet<Flight>();
        }

        public decimal Id { get; set; }
        public string? Airportname { get; set; }
        public string? Iatacode { get; set; }
        public decimal? Longitude { get; set; }
        public decimal? Latitude { get; set; }
        public string? Airportimage { get; set; }
        public decimal? Cityid { get; set; }

        public virtual City? City { get; set; }
        public virtual ICollection<Flight> FlightDepartureairports { get; set; }
        public virtual ICollection<Flight> FlightDestinationairports { get; set; }
    }
}
