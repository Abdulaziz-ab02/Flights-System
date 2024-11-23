using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class Facility
    {
        public Facility()
        {
            DegreeFacilities = new HashSet<DegreeFacility>();
        }

        public decimal Id { get; set; }
        public string? Facilityname { get; set; }
        public string? Facilityimage { get; set; }

        public virtual ICollection<DegreeFacility> DegreeFacilities { get; set; }
    }
}
