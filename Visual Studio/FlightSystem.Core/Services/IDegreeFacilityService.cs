using FlightSystem.Core.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Services
{
    public interface IDegreeFacilityService
    {
        public void CreateDegreeFacility(DegreeFacility degreeFacility);
        public void UpdateDegreeFacility(DegreeFacility degreeFacility);
        public void DeleteDegreeFacility(int id);
        public List<Facility> GetAvailableFacilitiesForDegree(int degreeId);
    }
}
