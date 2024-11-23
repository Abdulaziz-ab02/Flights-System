using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.DTO
{
    public class FlightDTO
    {
        public int Id { get; set; }
        public string FlightNumber { get; set; }
        public int Capacity { get; set; }
        public decimal PricePerPassenger { get; set; }
        public DateTime DepartureDate { get; set; }
        public DateTime DestinationDate { get; set; }
        public string Status { get; set; }
        public decimal DiscountValue { get; set; }
        public string AirlineName { get; set; }
        public string AirlineImage { get; set; }
        public string DepartureAirportName { get; set; }
                                                                                       
        public string DepartureIATACode { get; set; }
        public decimal DepartureLongitude { get; set; }
        public decimal DepartureLatitude { get; set; }
        public string DepartureCityName { get; set; }
        public string DestinationAirportName { get; set; }
        public string DestinationIATACode { get; set; }
        public decimal DestinationLongitude { get; set; }
        public decimal DestinationLatitude { get; set; }
        public string DestinationCityName { get; set; }
        public string DegreeName { get; set; }
    }

}
