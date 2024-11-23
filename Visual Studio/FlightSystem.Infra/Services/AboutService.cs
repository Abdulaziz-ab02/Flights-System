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
    public class AboutService : IAboutService
    {
        private readonly IAboutRepository _aboutRepository;
        public AboutService(IAboutRepository aboutRepository)
        {
            _aboutRepository = aboutRepository;
        }

        public List<Aboutu> GetAll()
        {
            return _aboutRepository.GetAll();
        }
        public void UpdateAbout(Aboutu aboutus)
        {
            _aboutRepository.UpdateAbout(aboutus);
        }
    }
}
