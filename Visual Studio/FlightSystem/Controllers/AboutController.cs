using FlightSystem.Core.Data;
using FlightSystem.Core.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AboutController : ControllerBase
    {

        private readonly IAboutService _aboutService;
        public AboutController(IAboutService aboutService)
        {
            _aboutService = aboutService;
        }

        [HttpGet]
        public List<Aboutu> GetAll()
        {
            return _aboutService.GetAll();
        }

        [HttpPut]
        [Route("UpdateAbout")]
        public void UpdateAbout(Aboutu aboutus)
        {
            _aboutService.UpdateAbout(aboutus);
        }

        [Route("uploadImage")]
        [HttpPost]
        public Aboutu UploadImage()
        {
            var file = Request.Form.Files[0];
            var fileName = Guid.NewGuid().ToString() + "_" + file.FileName;
            var fullPath = Path.Combine("C:\\Users\\wasse\\Desktop\\FlightProject_Local\\FlightProject\\src\\assets\\Images", fileName);

            using (var stream = new FileStream(fullPath, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            Aboutu item = new Aboutu();
            item.Aboutimage = fileName;
            return item;
        }


    }
}
