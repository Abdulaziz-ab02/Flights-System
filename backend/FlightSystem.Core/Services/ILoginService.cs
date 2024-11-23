using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Services
{
    public interface ILoginService
    {
        public string Auth(Login login);
        public string AirlineAuth(Login login);
    }
}
