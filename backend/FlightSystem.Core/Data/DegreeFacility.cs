using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class DegreeFacility
    {
        public decimal Id { get; set; }
        public decimal? Degreeid { get; set; }
        public decimal? Facilityid { get; set; }

        public virtual Degree? Degree { get; set; }
        public virtual Facility? Facility { get; set; }
    }
}
