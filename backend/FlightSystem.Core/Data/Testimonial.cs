using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class Testimonial
    {
        public decimal Id { get; set; }
        public string? Testimonialcontent { get; set; }
        public decimal? Rating { get; set; }
        public DateTime? Testimonialdate { get; set; }
        public string? Testimonialstatus { get; set; }
        public decimal? Userid { get; set; }

        public virtual User? User { get; set; }
    }
}
