using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.DTO
{
    public class FlightForSearchDTO
    {
        public DateTime? Departuredate { get; set; }
        public int? DeparturePlaceId { get; set; }
        public int? DestenationPlaceId { get; set; }
        public int? DegreenameId { get; set; }


    }
}
