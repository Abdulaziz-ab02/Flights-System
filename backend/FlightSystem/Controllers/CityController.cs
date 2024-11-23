using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using FlightSystem.Core.Services;
using FlightSystem.Infra.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CityController : ControllerBase
    {
        private readonly ICityService _cityService;
        public CityController(ICityService cityService)
        {
            _cityService = cityService;
        }

        [HttpPost]
        [Route("CreateCity")]
        public void CreateCity(City city)
        {
            _cityService.CreateCity(city);
        }

        [HttpPut]
        [Route("UpdateCity")]
        public void UpdateCity(City city)
        {
            _cityService.UpdateCity(city);
        }

        [HttpDelete]
        [Route("DeleteCity/{id}")]
        public void DeleteCity(int id)
        {
            _cityService.DeleteCity(id);
        }

        [HttpGet]
        [Route("GetCityById/{id}")]
        public List<City> GetCityById(int id)
        {
            return _cityService.GetCityById(id);

        }

        [HttpGet]
        [Route("GetAllCities")]
        public List<City> GetAllCities()
        {
            return _cityService.GetAllCities();

        }
        [HttpGet]
        [Route("GetCitiesByCountry/{countryId}")]
        public List<City> GetCitiesByCountry(int countryId)
        {
            return _cityService.GetCitiesByCountry(countryId);

        }
        [Route("uploadImage")]
        [HttpPost]
        public City UploadImage()
        {
            var file = Request.Form.Files[0];
            var fileName = Guid.NewGuid().ToString() + "_" + file.FileName;
            var fullPath = Path.Combine("C:\\Users\\wasse\\Desktop\\FlightProject_Local\\FlightProject\\src\\assets\\Images", fileName);

            using (var stream = new FileStream(fullPath, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            City item = new City();
            item.Cityimage = fileName;
            return item;
        }

    }
}
