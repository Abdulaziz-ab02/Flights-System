using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class Partner
    {
        public decimal Id { get; set; }
        public string? Firstname { get; set; }
        public string? Lastname { get; set; }
        public string? Nationalnumber { get; set; }
        public decimal? Userid { get; set; }

        public virtual User? User { get; set; }
    }
}
