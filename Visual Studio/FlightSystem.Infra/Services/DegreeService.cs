using FlightSystem.Core.Data;
using FlightSystem.Core.Repository;
using FlightSystem.Core.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Services
{
    public class DegreeService : IDegreeService
    {
        private readonly IDegreeRepository _degreeRepository;

        public DegreeService(IDegreeRepository degreeRepository)
        {
            _degreeRepository = degreeRepository;
        }

        public void CreateDegree(Degree degree)
        {
            _degreeRepository.CreateDegree(degree);
        }
        public void UpdateDegree(Degree degree)
        {
            _degreeRepository.UpdateDegree(degree);
        }
        public void DeleteDegree(int id)
        {
            _degreeRepository.DeleteDegree(id);
        }
        public List<Degree> GetAllDegrees()
        {
            return _degreeRepository.GetAllDegrees();   
        }

    }
}
