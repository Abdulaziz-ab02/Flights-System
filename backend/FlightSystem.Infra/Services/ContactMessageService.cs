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
    public class ContactMessageService : IContactMessageService
    {
        private readonly IContactMessageRepository _contactMessageRepository;
        public ContactMessageService(IContactMessageRepository contactMessageRepository) { 
            _contactMessageRepository = contactMessageRepository;
        }

        public List<ContactMessage> GetAllContactMessages()
        {
            return _contactMessageRepository.GetAllContactMessages();
        }
        public void CreateContactMessage(ContactMessage message)
        {
            _contactMessageRepository.CreateContactMessage(message);
        }

    }
}
