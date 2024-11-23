using FlightSystem.Core.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Repository
{
    public interface ICityRepository
    {
        public void CreateCity(City city);
        public void UpdateCity(City city);
        public void DeleteCity(int id);
        public List<City> GetAllCities();
        public List<City> GetCityById(int id);
        public List<City> GetCitiesByCountry(int countryId);

    }
}
