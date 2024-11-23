using FlightSystem.Core.Data;
using FlightSystem.Core.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DegreeController : ControllerBase
    {
        private readonly IDegreeService _degreeService;
        public DegreeController(IDegreeService degreeService)
        {
            _degreeService = degreeService;
        }
        

        [HttpPost]
        [Route("CreateDegree")]
        public void CreateDegree(Degree degree)
        {
            _degreeService.CreateDegree(degree);
        }
               
        [HttpPut]
        [Route("UpdateDegree")]
        public void UpdateDegree(Degree degree)
        {
            _degreeService.UpdateDegree(degree);
        }

        [HttpDelete]
        [Route("DeleteDegree/{id}")]
        public void DeleteDegree(int id)
        {
            _degreeService.DeleteDegree(id);
        }
        [HttpGet]
        [Route("GetAllDegrees")]
        public List<Degree> GetAllDegrees()
        {
            return _degreeService.GetAllDegrees();
        }



    }
}
