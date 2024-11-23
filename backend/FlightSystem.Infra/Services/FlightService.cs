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
    public class FlightService : IFlightService
    {
        private readonly IFlightRepository _flightRepository;
        public FlightService(IFlightRepository flightRepository)
        {
            _flightRepository = flightRepository;
        }
        public void CreateFlight(Flight flight)
        {
            _flightRepository.CreateFlight(flight);
        }
        public void UpdateFlight(Flight flight)
        {
            _flightRepository.UpdateFlight(flight);
        }
        public void DeleteFlight(int id)
        {
            _flightRepository.DeleteFlight(id);
        }
        public FlightDTO FetchFlightByID(int id)
        {
            return _flightRepository.FetchFlightByID(id);
        }
        public FlightDTO FetchFlightByFlightNumber(string flightNumber)
        {
           return _flightRepository.FetchFlightByFlightNumber(flightNumber);
        }
        public List<FlightDTO> FetchAllFlights()
        {
            return _flightRepository.FetchAllFlights();
        }
        public List<ReturnFlightSearch> FetchFlightBasedOnUserSearch(FlightForSearchDTO obj)
        {
            return _flightRepository.FetchFlightBasedOnUserSearch(obj);
        }
        public List<DfDTO> GetAllFacilitesByDegreeId(int id)
        {
            return _flightRepository.GetAllFacilitesByDegreeId(id);
        }

        public List<FlightDTO> GetAllFlightsByAirlineID(int airlineId)
        {
            return _flightRepository.GetAllFlightsByAirlineID(airlineId);
        }

    }
}
