using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class Country
    {
        public Country()
        {
            Cities = new HashSet<City>();
        }

        public decimal Id { get; set; }
        public string? Countryname { get; set; }

        public virtual ICollection<City> Cities { get; set; }
    }
}
