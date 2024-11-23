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
    public class DegreeFacilityRepository : IDegreeFacilityRepository
    {
        private readonly IDbContext _dbContext;
        public DegreeFacilityRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public void CreateDegreeFacility(DegreeFacility degreeFacility)
        {
            var p = new DynamicParameters();
            p.Add("Degree_id", degreeFacility.Degreeid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("Facility_id", degreeFacility.Facilityid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("degree_facility_Package.CreateDegreeFacility", p, commandType: CommandType.StoredProcedure);

        }
        public void UpdateDegreeFacility(DegreeFacility degreeFacility)
        {
            var p = new DynamicParameters();
            p.Add("dfid", degreeFacility.Id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("Degree_id", degreeFacility.Degreeid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("Facility_id", degreeFacility.Facilityid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("degree_facility_Package.UpdateDegreeFacility", p, commandType: CommandType.StoredProcedure);

        }
        public void DeleteDegreeFacility(int id)
        {
            var p = new DynamicParameters();
            p.Add("dfid", id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("degree_facility_Package.DeleteDegreeFacility", p, commandType: CommandType.StoredProcedure);
        }


        public List<Facility> GetAvailableFacilitiesForDegree(int degreeId)
        {
            var p = new DynamicParameters();
            p.Add("Degree_id", degreeId, dbType: DbType.Int32, direction: ParameterDirection.Input);

            // Execute the stored procedure and map the result to a list of Facility objects
            var result = _dbContext.Connection.Query<Facility>("degree_facility_Package.GetAvailableFacilitiesForDegree",
                p,
                commandType: CommandType.StoredProcedure
            ).ToList(); // Convert the result to a List<Facility>

            return result;
        }

    }
}
