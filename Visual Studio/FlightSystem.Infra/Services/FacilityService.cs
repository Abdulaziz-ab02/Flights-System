using FlightSystem.Core.Data;
using FlightSystem.Core.Repository;
using FlightSystem.Core.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Services
{
    public class FacilityService : IFacilityService
    {
        private readonly IFacilityRepository _facilityRepository;

        public FacilityService(IFacilityRepository facilityRepository)
        {
            _facilityRepository = facilityRepository;
        }

        public List<Facility> GetAllFacility()
        {
            return _facilityRepository.GetAllFacility();
        }
        public void CreateFacility(Facility facility)
        {
            _facilityRepository.CreateFacility(facility);
        }
        public void UpdateFacility(Facility facility)
        {
            _facilityRepository.UpdateFacility(facility);
        }
        public void DeleteFacility(int id)
        {
            _facilityRepository.DeleteFacility(id);
        }



    }
}
