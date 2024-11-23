using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.DTO
{
    public class AirlineDTO
    {
        public decimal Id { get; set; }
        public string? Airlinename { get; set; }
        public string? Airlineimage { get; set; }
        public string? Airlineemail { get; set; }
        public string? Airlineaddress { get; set; }
        public string? Activationstatus { get; set; }


        public string? Username { get; set; }
        public string? Password { get; set; }
        public decimal? Roleid { get; set; }

    }
}
