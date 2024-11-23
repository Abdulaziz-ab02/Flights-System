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
    public class HomeService : IHomeService
    {
        private readonly IHomeRepository _homeRepository;
        public HomeService(IHomeRepository homeRepository)
        {
            _homeRepository = homeRepository;
        }


        public List<Home> GetAll()
        {
            return _homeRepository.GetAll();
        }
        public void UpdateHome(Home home)
        {
            _homeRepository.UpdateHome(home);
        }

    }
}
