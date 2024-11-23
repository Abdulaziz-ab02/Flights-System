using FlightSystem.Core.Data;
using FlightSystem.Core.Services;
using FlightSystem.Infra.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CountryController : ControllerBase
    {
        private readonly ICountryService _countryService;
        public CountryController(ICountryService countryService)
        {
            _countryService = countryService;
        }

        [HttpPost]
        [Route("CreateCountry")]
        public void CreateCountry(Country country)
        {
            _countryService.CreateCountry(country);
        }

        [HttpPut]
        [Route("UpdateCountry")]
        public void UpdateCountry(Country country)
        {
            _countryService.UpdateCountry(country);
        }

        [HttpDelete]
        [Route("DeleteCountry/{id}")]
        public void DeleteCountry(int id)
        {
            _countryService.DeleteCountry(id);
        }

        [HttpGet]
        [Route("GetCountryById/{id}")]
        public List<Country> GetCountryById(int id)
        {
            return _countryService.GetCountryById(id);
           
        }

        [HttpGet]
        [Route("GetAllCountries")]
        public List<Country> GetAllCountries()
        {
            return _countryService.GetAllCountries();
            
        }



    }
}
