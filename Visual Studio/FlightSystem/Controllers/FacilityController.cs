using FlightSystem.Core.Data;
using FlightSystem.Core.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class FacilityController : ControllerBase
    {
        private readonly IFacilityService _facilityService;
        public FacilityController(IFacilityService facilityService)
        {
            _facilityService = facilityService;
        }

        [HttpGet]
        public List<Facility> GetAllFacility()
        {
            return _facilityService.GetAllFacility();
        }

        [HttpPost]
        [Route("CreateFacility")]
        public void CreateFacility(Facility facility)
        {
            _facilityService.CreateFacility(facility);
        }

        [HttpPut]
        [Route("UpdateFacility")]
        public void UpdateFacility(Facility facility)
        {
            _facilityService.UpdateFacility(facility);
        }

        [HttpDelete]
        [Route("DeleteFacility/{id}")]
        public void DeleteFacility(int id)
        {
            _facilityService.DeleteFacility(id);
        }
    }
}
