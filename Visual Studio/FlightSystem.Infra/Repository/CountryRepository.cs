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
    public class CountryRepository : ICountryRepository
    {
        private readonly IDbContext _dbContext;
        public CountryRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;

        }

        public void CreateCountry(Country country)
        {
            var p = new DynamicParameters();
            p.Add("p_CountryName", country.Countryname, DbType.String, ParameterDirection.Input);
           
            _dbContext.Connection.Execute("COUNTRY_PKG.CREATE_COUNTRY", p, commandType: CommandType.StoredProcedure);
        }
        public void UpdateCountry(Country country)
        {
            var p = new DynamicParameters();
            p.Add("p_ID", country.Id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_CountryName", country.Countryname, DbType.String, ParameterDirection.Input);

            _dbContext.Connection.Execute("COUNTRY_PKG.UPDATE_COUNTRY", p, commandType: CommandType.StoredProcedure);
        }
        public void DeleteCountry(int id)
        {
            var p = new DynamicParameters();
            p.Add("p_Id", id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("COUNTRY_PKG.DELETE_COUNTRY", p, commandType: CommandType.StoredProcedure);

        }
        public List<Country> GetCountryById(int id)
        {
            var p = new DynamicParameters();
            p.Add("p_Id", id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            return _dbContext.Connection.Query<Country>("COUNTRY_PKG.GET_COUNTRY_BY_ID",p, commandType: CommandType.StoredProcedure).ToList();
          
        }
        public List<Country> GetAllCountries()
        {
            return _dbContext.Connection.Query<Country>("COUNTRY_PKG.GET_ALL_COUNTRIES", commandType: CommandType.StoredProcedure).ToList();

        }

    }
}
