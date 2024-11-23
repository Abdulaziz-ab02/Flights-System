using FlightSystem.Core.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Services
{
    public interface IAboutService
    {
        public List<Aboutu> GetAll();
        public void UpdateAbout(Aboutu aboutus);
    }
}
