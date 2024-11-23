using FlightSystem.Core.Data;
using FlightSystem.Core.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {

        private readonly ILoginService _loginService;
        public LoginController(ILoginService loginService)
        {
            _loginService = loginService;
        }


        [HttpPost]
        [Route("Login")]
        public IActionResult Auth(Login login)
        {
            var token = _loginService.Auth(login);
            if (token == null)
            {
                return Unauthorized();
            }
            else
            {
                return Ok(token);
            }
        }
        [HttpPost]
        [Route("AirlineLogin")]

        public IActionResult AirlineAuth(Login login)
        {
            var token = _loginService.AirlineAuth(login);
            if (token == null)
            {
                return Unauthorized();
            }
            else
            {
                return Ok(token);
            }


        }


    }
}
