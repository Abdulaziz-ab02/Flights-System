using FlightSystem.Core.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Repository
{
    public interface IDegreeRepository
    {
        public void CreateDegree(Degree degree);
        public void UpdateDegree(Degree degree);
        public void DeleteDegree(int id);
        public List<Degree> GetAllDegrees();


    }
}
