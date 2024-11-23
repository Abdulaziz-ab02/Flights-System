using FlightSystem.Core.DTO;
using FlightSystem.Core.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AirlineController : ControllerBase
    {
        private readonly IAirlineService _airlineService;
        public AirlineController(IAirlineService airlineService)
        {
            _airlineService = airlineService;
        }

        [HttpGet]
        public List<AirlineDTO> GetAllAirline()
        {
            return _airlineService.GetAllAirline();
        }

        [HttpGet]
        [Route("GetAirlineById/{id}")]
        public AirlineDTO GetAirlineById(int id)
        {
            return _airlineService.GetAirlineById(id);
        }

        [HttpPost]
        [Route("CreateAirline")]
        public void CreateAirline(AirlineDTO airlinedto)
        {
            _airlineService.CreateAirline(airlinedto);
        }

        [HttpPut]
        [Route("UpdateAirline")]
        public void UpdateAirline(AirlineDTO airlinedto)
        {
            _airlineService.UpdateAirline(airlinedto);
        }

        [HttpPut]
        [Route("ChangeAirlineActivationStatus/{id}/{status}")]
        public void ChangeAirlineActivationStatus(int id, string status)
        {
            _airlineService.ChangeAirlineActivationStatus(id, status);
        }

        [Route("uploadImage")]
        [HttpPost]
        public AirlineDTO UploadImage()
        {
            var file = Request.Form.Files[0];
            var fileName = Guid.NewGuid().ToString() + "_" + file.FileName;
            var fullPath = Path.Combine("C:\\Users\\wasse\\Desktop\\FlightProject_Local\\FlightProject\\src\\assets\\Images", fileName);

            using (var stream = new FileStream(fullPath, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            AirlineDTO item = new AirlineDTO();
            item.Airlineimage = fileName;
            return item;
        }

        [HttpDelete]
        [Route("deleteAirline/{id}")]
        public void DeleteAirline(int id) {

            _airlineService.DeleteAirline(id);
        }




    }
}
