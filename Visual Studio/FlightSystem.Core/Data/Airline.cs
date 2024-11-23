using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class Airline
    {
        public Airline()
        {
            Flights = new HashSet<Flight>();
            Logins = new HashSet<Login>();
        }

        public decimal Id { get; set; }
        public string? Airlinename { get; set; }
        public string? Airlineimage { get; set; }
        public string? Airlineemail { get; set; }
        public string? Airlineaddress { get; set; }
        public string? Activationstatus { get; set; }

        public virtual ICollection<Flight> Flights { get; set; }
        public virtual ICollection<Login> Logins { get; set; }
    }
}
