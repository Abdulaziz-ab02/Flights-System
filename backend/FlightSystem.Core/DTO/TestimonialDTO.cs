using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.DTO
{
    public class TestimonialDTO
    {
        public decimal Id { get; set; }

        public decimal Userid { get; set; }
        public string? Testimonialcontent { get; set; }
        public decimal? Rating { get; set; }
        public DateTime? Testimonialdate { get; set; }
        public string? Testimonialstatus { get; set; }


        public string? Firstname { get; set; }
        public string? Lastname { get; set; }
        public string? Image { get; set; }
    }
}
