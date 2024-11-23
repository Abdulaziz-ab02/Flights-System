using FlightSystem.Core.Data;
using FlightSystem.Core.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HomeController : ControllerBase
    {
        private readonly IHomeService _homeService;
        public HomeController(IHomeService homeService)
        {
            _homeService = homeService;
        }


        [HttpGet]
        public List<Home> GetAll()
        {
            return _homeService.GetAll();
        }

        [HttpPut]
        [Route("UpdateHome")]
        public void UpdateHome(Home home)
        {
            _homeService.UpdateHome(home);
        }


        [Route("uploadImage")]
        [HttpPost]
        public Home UploadImage()
        {
            var file = Request.Form.Files[0];
            var fileName = Guid.NewGuid().ToString() + "_" + file.FileName;
            var fullPath = Path.Combine("C:\\Users\\wasse\\Desktop\\FlightProject_Local\\FlightProject\\src\\assets\\Images", fileName);

            using (var stream = new FileStream(fullPath, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            Home item = new Home();
            item.Homeimage = fileName;
            return item;
        }

    }
}
