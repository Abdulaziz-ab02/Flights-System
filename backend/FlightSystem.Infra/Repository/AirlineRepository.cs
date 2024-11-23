using Dapper;
using FlightSystem.Core.Common;
using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using FlightSystem.Core.Repository;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Repository
{
    public class AirlineRepository : IAirlineRepository
    {
        private readonly IDbContext _dbContext;
        public AirlineRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public List<AirlineDTO> GetAllAirline()
        {
            var result = _dbContext.Connection.Query<AirlineDTO>("airline_Package.GetAllAirline",
                commandType: CommandType.StoredProcedure);
            return result.ToList();
        }

        public AirlineDTO GetAirlineById(int id)
        {
            var p = new DynamicParameters();
            p.Add("a_id", id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            var result = _dbContext.Connection.Query<AirlineDTO>("airline_Package.GetAirlineById", p, commandType: CommandType.StoredProcedure);
            return result.SingleOrDefault();
        }

        public void CreateAirline(AirlineDTO airlinedto)
        {
            var p = new DynamicParameters();
            p.Add("Airline_Name", airlinedto.Airlinename, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("Airline_image", airlinedto.Airlineimage, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("Airline_Email", airlinedto.Airlineemail, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("Airline_Address", airlinedto.Airlineaddress, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("Activation_Status", airlinedto.Activationstatus, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("a_username", airlinedto.Username, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("a_pass", airlinedto.Password, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("a_roleid", airlinedto.Roleid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("airline_Package.CreateAirline", p, commandType: CommandType.StoredProcedure);
            
        }

        public void UpdateAirline(AirlineDTO airlinedto)
        {
            var p = new DynamicParameters();
            p.Add("a_id", airlinedto.Id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("Airline_Name", airlinedto.Airlinename, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("Airline_image", airlinedto.Airlineimage, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("Airline_Email", airlinedto.Airlineemail, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("Airline_Address", airlinedto.Airlineaddress, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("Activation_Status", airlinedto.Activationstatus, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("a_username", airlinedto.Username, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("a_pass", airlinedto.Password, dbType: DbType.String, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("airline_Package.UpdateAirline", p, commandType: CommandType.StoredProcedure);

        }

        public void ChangeAirlineActivationStatus(int id, string status)
        {
            var p = new DynamicParameters();
            p.Add("a_id", id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("Activation_Status", status, dbType: DbType.String, direction: ParameterDirection.Input);
            
            _dbContext.Connection.Execute("airline_Package.Change_Activation_Status", p, commandType: CommandType.StoredProcedure);
        }

        public void DeleteAirline(int id)
        {
            var p = new DynamicParameters();
            p.Add("a_id", id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("airline_Package.Delete_Airline", p, commandType: CommandType.StoredProcedure);

        }

    }
}
