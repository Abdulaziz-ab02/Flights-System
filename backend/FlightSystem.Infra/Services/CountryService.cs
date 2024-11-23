using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using FlightSystem.Core.Repository;
using FlightSystem.Core.Services;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Services
{
    public class CountryService : ICountryService
    {
        private readonly ICountryRepository _countryRepository;

        public CountryService(ICountryRepository countryRepository)
        {
            _countryRepository = countryRepository;
        }

        public void CreateCountry(Country country)
        {
            _countryRepository.CreateCountry(country);
        }
        public void UpdateCountry(Country country)
        {
            _countryRepository.UpdateCountry(country);
        }
        public void DeleteCountry(int id)
        {
            _countryRepository.DeleteCountry(id);
        }
        public List<Country> GetCountryById(int id)
        {
           return _countryRepository.GetCountryById(id);
        }

        public List<Country> GetAllCountries()
        {
            return _countryRepository.GetAllCountries();

        }
    }
}
