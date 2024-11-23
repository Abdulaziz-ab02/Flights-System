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
    public class AirportRepository : IAirportRepository
    {
        private readonly IDbContext _dbContext;
        public AirportRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;

        }
        public void CreateAirport(Airport airport)
        {
            var p = new DynamicParameters();
            p.Add("p_AirportName", airport.Airportname, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("p_IATACode", airport.Iatacode, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("p_Longitude", airport.Longitude, dbType: DbType.Double, direction: ParameterDirection.Input);
            p.Add("p_Latitude", airport.Latitude, dbType: DbType.Double, direction: ParameterDirection.Input);
            p.Add("p_AirportImage", airport.Airportimage, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("p_CityId", airport.Cityid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("AirPort_Package.CreateAirport", p, commandType: CommandType.StoredProcedure);
        }
        public void UpdateAirport(Airport airport)
        {
            var p = new DynamicParameters();
            p.Add("p_ID", airport.Id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_AirportName", airport.Airportname, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("p_IATACode", airport.Iatacode, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("p_Longitude", airport.Longitude, dbType: DbType.Double, direction: ParameterDirection.Input);
            p.Add("p_Latitude", airport.Latitude, dbType: DbType.Double, direction: ParameterDirection.Input);
            p.Add("p_AirportImage", airport.Airportimage, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("p_CityId", airport.Cityid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("AirPort_Package.UpdateAirport", p, commandType: CommandType.StoredProcedure);
        }
        public void DeleteAirport(int id)
        {
            var p = new DynamicParameters();
            p.Add("p_ID", id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("AirPort_Package.DeleteAirport", p, commandType: CommandType.StoredProcedure);

        }

        public AirportDTO FetchAirportById(int id)
        {
            var p = new DynamicParameters();
            p.Add("p_ID",id,dbType:DbType.Int32,direction:ParameterDirection.Input);
            var result = _dbContext.Connection.Query<AirportDTO>("AirPort_Package.FetchAirportByID",
                p,commandType:CommandType.StoredProcedure);
            return result.FirstOrDefault();
        }
        public List<AirportDTO> FetchAllAirports()
        {
            var res = _dbContext.Connection.Query<AirportDTO>("AirPort_Package.FetchAllAirports",
                commandType:CommandType.StoredProcedure);
            return res.ToList();

        }

    }
}
