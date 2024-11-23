using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Repository
{
    public interface IAirportRepository
    {
        public void CreateAirport(Airport airport);
        public void UpdateAirport(Airport airport);
        public void DeleteAirport(int id);
        public AirportDTO FetchAirportById(int id);
        public List<AirportDTO> FetchAllAirports();
    }
}
