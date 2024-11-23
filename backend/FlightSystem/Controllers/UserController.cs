using FlightSystem.Core.DTO;
using FlightSystem.Core.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        // Constructor Injection for the IUserService
        public UserController(IUserService userService)
        {
            _userService = userService;
        }


        [HttpPost]
        [Route("CreateUser")]
        public void CreateUser(UserDTO userDto)
        {
            _userService.CreateUser(userDto);
        }


        [HttpPut]
        [Route("UpdateUser")]
        public void UpdateUser(UserDTO userDto)
        {
            _userService.UpdateUser(userDto);
        }



        [HttpGet]
        [Route("GetAllUsers")]
        public List<UserDTO> GetAllUsers()
        {
            return _userService.GetAllUsers();
        }


        [HttpGet]
        [Route("getUserById/{id}")]
        public UserDTO GetUserById(int id )
        {
            return _userService.GetUserById(id);
        }



        [Route("uploadImage")]
        [HttpPost]
        public UserDTO UploadImage()
        {
            var file = Request.Form.Files[0];
            var fileName = Guid.NewGuid().ToString() + "_" + file.FileName;
            /*var fullPath = Path.Combine("Images", fileName);*/
            //for angular project
            var fullPath = Path.Combine("C:\\Users\\wasse\\Desktop\\FlightProject_Local\\FlightProject\\src\\assets\\Images", fileName);

            using (var stream = new FileStream(fullPath, FileMode.Create))
            {
                file.CopyTo(stream);
            }
            UserDTO item = new UserDTO();
            item.Image = fileName;
            return item;
        }


        [Route("CheckUserExists")]
        [HttpPost]
        public IActionResult CheckUserExists(UserDTO user)
        {
            string result = _userService.CheckUserExists(user);
            return Ok(new { result });
        }



        [HttpGet]
        [Route("GetUsersWithPartners")]
        public List<UserDTO> GetUsersWithPartners()
        {
            return _userService.GetUsersWithPartners();
        }


    }
}
