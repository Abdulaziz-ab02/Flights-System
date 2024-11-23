using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.DTO
{
    public class AirportDTO
    {
        public decimal Id { get; set; }
        public string? Airportname { get; set; }
        public string? Iatacode { get; set; }
        public decimal? Longitude { get; set; }
        public decimal? Latitude { get; set; }
        public string? Airportimage { get; set; }
        public string? Cityname { get; set; }
        public decimal? Cityid { get; set; }

    }
}
