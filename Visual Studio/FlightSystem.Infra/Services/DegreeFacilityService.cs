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
    public class DegreeFacilityService : IDegreeFacilityService
    {
        private readonly IDegreeFacilityRepository _degreefacilityRepository;

        public DegreeFacilityService(IDegreeFacilityRepository degreefacilityRepository)
        {
            _degreefacilityRepository = degreefacilityRepository;
        }

        public void CreateDegreeFacility(DegreeFacility degreeFacility)
        {
            _degreefacilityRepository.CreateDegreeFacility(degreeFacility);
        }
        public void UpdateDegreeFacility(DegreeFacility degreeFacility)
        {
            _degreefacilityRepository.UpdateDegreeFacility(degreeFacility);
        }
        public void DeleteDegreeFacility(int id)
        {
            _degreefacilityRepository.DeleteDegreeFacility(id);
        }

        public List<Facility> GetAvailableFacilitiesForDegree(int degreeId)
        {
            return _degreefacilityRepository.GetAvailableFacilitiesForDegree(degreeId);

        }
    }
}
