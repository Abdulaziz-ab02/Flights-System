using FlightSystem.Core.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Repository
{
    public interface ICountryRepository
    {
        public void CreateCountry(Country country);
        public void UpdateCountry(Country country);
        public void DeleteCountry(int id);
        public List<Country> GetAllCountries();
        public List<Country> GetCountryById(int id);
    }
}
