using FlightSystem.Core.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Services
{
    public interface IContactMessageService
    {
        public List<ContactMessage> GetAllContactMessages();
        public void CreateContactMessage(ContactMessage message);
    }
}
