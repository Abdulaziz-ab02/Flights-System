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
    public class AirlineService : IAirlineService
    {
        private readonly IAirlineRepository _airlineRepository;
        public AirlineService(IAirlineRepository airlineRepository)
        {
            _airlineRepository = airlineRepository;
        }

        public List<AirlineDTO> GetAllAirline()
        {
            return _airlineRepository.GetAllAirline();
        }
        public AirlineDTO GetAirlineById(int id)
        {
            return _airlineRepository.GetAirlineById(id);
        }
        public void CreateAirline(AirlineDTO airlinedto)
        {
            _airlineRepository.CreateAirline(airlinedto);
        }
        public void UpdateAirline(AirlineDTO airlinedto)
        {
            _airlineRepository.UpdateAirline(airlinedto);
        }
        public void ChangeAirlineActivationStatus(int id, string status)
        {
            _airlineRepository.ChangeAirlineActivationStatus(id, status);
        }

        public void DeleteAirline(int id)
        {
            _airlineRepository.DeleteAirline(id);
        }
    }
}
