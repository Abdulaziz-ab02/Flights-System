using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using FlightSystem.Core.Repository;
using FlightSystem.Core.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Services
{
    public class AirportService :IAirportService
    {
        private readonly IAirportRepository _airportRepository;

        public AirportService(IAirportRepository airportRepository)
        {
            _airportRepository = airportRepository;
        }
        public void CreateAirport(Airport airport)
        {
            _airportRepository.CreateAirport(airport);
        }
        public void UpdateAirport(Airport airport)
        {
            _airportRepository.UpdateAirport(airport);
        }
        public void DeleteAirport(int id)
        {
            _airportRepository.DeleteAirport(id);
        }
        public AirportDTO FetchAirportById(int id)
        {
            return _airportRepository.FetchAirportById(id);
        }
        public List<AirportDTO> FetchAllAirports()
        {
           return _airportRepository.FetchAllAirports();
        }


    }
}
