using FlightSystem.Core.DTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Repository
{
    public interface IAirlineRepository
    {
        public List<AirlineDTO> GetAllAirline();
        public AirlineDTO GetAirlineById(int id);
        public void CreateAirline(AirlineDTO airlinedto);
        public void UpdateAirline(AirlineDTO airlinedto);
        public void ChangeAirlineActivationStatus(int id, string status);
        public void DeleteAirline(int id);

    }
}
