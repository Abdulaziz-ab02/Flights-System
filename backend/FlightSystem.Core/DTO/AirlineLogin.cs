using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.DTO
{
    public  class AirlineLogin
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? Activationstatus { get; set; }
        public decimal? Roleid { get; set; }
        public decimal? Airlineid { get; set; }


    }
}
