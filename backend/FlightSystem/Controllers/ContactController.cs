using FlightSystem.Core.Data;
using FlightSystem.Core.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ContactController : ControllerBase
    {
        private readonly IContactService _contactService;
        public ContactController(IContactService contactService)
        {
            _contactService = contactService;
        }


        [HttpGet]
        public List<Contactu> GetAll()
        {
            return _contactService.GetAll();
        }

        [HttpPut]
        [Route("UpdateContact")]
        public void UpdateContact(Contactu contact)
        {
            _contactService.UpdateContact(contact);
        }
    }
}
