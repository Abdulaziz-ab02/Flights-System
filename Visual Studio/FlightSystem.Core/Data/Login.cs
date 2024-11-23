using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class Login
    {
        public decimal Id { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }
        public decimal? Roleid { get; set; }
        public decimal? Userid { get; set; }
        public decimal? Airlineid { get; set; }
        public string? Email { get; set; }

        public virtual Airline? Airline { get; set; }
        public virtual Role? Role { get; set; }
        public virtual User? User { get; set; }
    }
}
