using Dapper;
using FlightSystem.Core.Common;
using FlightSystem.Core.Data;
using FlightSystem.Core.Repository;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Repository
{
    public class CityRepository : ICityRepository
    {
        private readonly IDbContext _dbContext;
        public CityRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;

        }

        public void CreateCity(City city)
        {
            var p = new DynamicParameters();
            p.Add("p_CityName", city.Cityname, DbType.String, ParameterDirection.Input);
            p.Add("p_CityImage", city.Cityimage, DbType.String, ParameterDirection.Input);
            p.Add("p_CountryId", city.Countryid, DbType.String, ParameterDirection.Input);
            _dbContext.Connection.Execute("CITY_PKG.CREATE_CITY", p, commandType: CommandType.StoredProcedure);
        }
        public void UpdateCity(City city)
        {
            var p = new DynamicParameters();
            p.Add("p_ID", city.Id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_CityName", city.Cityname, DbType.String, ParameterDirection.Input);
            p.Add("p_CityImage", city.Cityimage, DbType.String, ParameterDirection.Input);
            p.Add("p_CountryId", city.Countryid, DbType.String, ParameterDirection.Input);
            _dbContext.Connection.Execute("CITY_PKG.UPDATE_CITY", p, commandType: CommandType.StoredProcedure);

        }
        public void DeleteCity(int id)
        {
            var p = new DynamicParameters();
            p.Add("p_Id", id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("CITY_PKG.DELETE_CITY", p, commandType: CommandType.StoredProcedure);
        }
        public List<City> GetAllCities()
        {
            return _dbContext.Connection.Query<City>("CITY_PKG.GET_ALL_CITIES", commandType: CommandType.StoredProcedure).ToList();
        }
        public List<City> GetCityById(int id)
        {
            var p = new DynamicParameters();
            p.Add("p_Id", id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            return _dbContext.Connection.Query<City>("CITY_PKG.GET_CITY_BY_ID", p, commandType: CommandType.StoredProcedure).ToList();
        }
        public List<City> GetCitiesByCountry(int countryId)
        {
            var p = new DynamicParameters();
            p.Add("p_CountryId", countryId, dbType: DbType.Int32, direction: ParameterDirection.Input);
            return _dbContext.Connection.Query<City>("CITY_PKG.GET_CITIES_BY_COUNTRY", p, commandType: CommandType.StoredProcedure).ToList();
        }
    }
}
