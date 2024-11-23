using FlightSystem.Core.Data;
using FlightSystem.Core.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ContactMessageController : ControllerBase
    {
        private readonly IContactMessageService _contactMessageService;
        public ContactMessageController(IContactMessageService contactMessageService)
        {
            _contactMessageService = contactMessageService;
        }

        [HttpGet]
        public List<ContactMessage> GetAllContactMessages()
        {
            return _contactMessageService.GetAllContactMessages();
        }

        [HttpPost]
        [Route("CreateContactMessage")]
        public void CreateContactMessage(ContactMessage message)
        {
            _contactMessageService.CreateContactMessage(message);
        }

    }
}
