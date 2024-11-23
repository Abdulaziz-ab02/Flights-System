using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Repository
{
    public interface IFlightRepository
    {
        public void CreateFlight(Flight flight);
        public void UpdateFlight(Flight flight);
        public void DeleteFlight(int id);
        public FlightDTO FetchFlightByID(int id);
        public FlightDTO FetchFlightByFlightNumber(string flightNumber);
        public List<FlightDTO> FetchAllFlights();
        public List<ReturnFlightSearch> FetchFlightBasedOnUserSearch(FlightForSearchDTO obj);
        public List<DfDTO> GetAllFacilitesByDegreeId(int id);

        public List<FlightDTO> GetAllFlightsByAirlineID(int airlineId);

    }
}
