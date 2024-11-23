using FlightSystem.Core.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Repository
{
    public interface IHomeRepository
    {
        public List<Home> GetAll();
        public void UpdateHome(Home home);
    }
}
