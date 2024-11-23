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
    public class CityService : ICityService
    {
        private readonly ICityRepository _cityRepository;

        public CityService(ICityRepository cityRepository)
        {
            _cityRepository = cityRepository;
        }

        public void CreateCity(City city) 
        {
            _cityRepository.CreateCity(city);
        }
        public void UpdateCity(City city)
        {
            _cityRepository.UpdateCity(city);
        }
        public void DeleteCity(int id)
        {
            _cityRepository.DeleteCity(id);
        }
        public List<City> GetAllCities()
        {
            return _cityRepository.GetAllCities();
        }

        public List<City> GetCityById(int id)
        {
            return _cityRepository.GetCityById(id);

        }
        public List<City> GetCitiesByCountry(int countryId)
        {
            return _cityRepository.GetCitiesByCountry(countryId);
        }
    }
    
}
