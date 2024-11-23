using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Repository
{
    public interface ILoginRepository
    {
        public Login Auth(Login login);
        public AirlineLogin AirlineAuth(Login login);

    }
}
