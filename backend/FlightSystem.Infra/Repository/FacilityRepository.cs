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
    public class FacilityRepository : IFacilityRepository
    {
        private readonly IDbContext _dbContext;
        public FacilityRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public List<Facility> GetAllFacility()
        {
            var res = _dbContext.Connection.Query<Facility>("facility_Package.GetAllFacility", commandType: CommandType.StoredProcedure);
            return res.ToList();
        }

        public void CreateFacility(Facility facility)
        {
            var p = new DynamicParameters();
            p.Add("Facility_Name", facility.Facilityname, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("Facility_image", facility.Facilityimage, dbType: DbType.String, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("facility_Package.CreateFacility", p, commandType: CommandType.StoredProcedure);
        }
        public void UpdateFacility(Facility facility)
        {
            var p = new DynamicParameters();
            p.Add("facid", facility.Id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("Facility_Name", facility.Facilityname, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("Facility_image", facility.Facilityimage, dbType: DbType.String, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("facility_Package.UpdateFacility", p, commandType: CommandType.StoredProcedure);
        }

        public void DeleteFacility(int id)
        {
            var p = new DynamicParameters();
            p.Add("facid", id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("facility_Package.DeleteFacility", p, commandType: CommandType.StoredProcedure);
        }
               


    }
}
