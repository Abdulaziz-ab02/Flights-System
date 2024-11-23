using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using FlightSystem.Core.Services;
using FlightSystem.Infra.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PartnerController : ControllerBase
    {
        private readonly IPartnerService _partnerService;

        // Constructor Injection for the IUserService
        public PartnerController(IPartnerService partnerService)
        {
            _partnerService = partnerService;
        }


        [HttpPost]
        [Route("CreatePartner")]
        public void CreatePartner(Partner partner)
        {
            _partnerService.CreatePartner(partner);
        }


        [HttpGet]
        [Route("getPartnerByUserId/{userId}")]
        public List<PartnerDTO> GetPartnersByUser(int userId)
        {
            return _partnerService.GetPartnersByUser(userId);
        }
    }
}
