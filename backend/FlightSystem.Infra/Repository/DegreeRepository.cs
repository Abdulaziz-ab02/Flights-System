using Dapper;
using FlightSystem.Core.Common;
using FlightSystem.Core.Data;
using FlightSystem.Core.Repository;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Repository
{
    public class DegreeRepository : IDegreeRepository
    {
        private readonly IDbContext _dbContext;
        public DegreeRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public void CreateDegree(Degree degree)
        {
            var p = new DynamicParameters();
            p.Add("Degree_Name", degree.Degreename, dbType: DbType.String, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("degree_Package.CreateDegree", p, commandType: CommandType.StoredProcedure);

        }

        public void UpdateDegree(Degree degree)
        {
            var p = new DynamicParameters();
            p.Add("degid", degree.Id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("Degree_Name", degree.Degreename, dbType: DbType.String, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("degree_Package.UpdateDegree", p, commandType: CommandType.StoredProcedure);

        }

        public void DeleteDegree(int id)
        {
            var p = new DynamicParameters();
            p.Add("degid", id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("degree_Package.DeleteDegree", p, commandType: CommandType.StoredProcedure);

        }
        public List<Degree> GetAllDegrees()
        {
            var result = _dbContext.Connection.Query<Degree>("degree_Package.GetAllDegrees", commandType: CommandType.StoredProcedure);
            return result.ToList();
        }



    }
}
