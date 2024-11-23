using FlightSystem.Core.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Services
{
    public interface IContactService
    {
        public List<Contactu> GetAll();
        public void UpdateContact(Contactu contact);
    }
}
