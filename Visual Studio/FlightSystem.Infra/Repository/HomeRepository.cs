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
    public class HomeRepository : IHomeRepository
    {
        private readonly IDbContext _dbContext;
        public HomeRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;
        }


        public List<Home> GetAll()
        {
            var result = _dbContext.Connection.Query<Home>("home_page_pkg.GetAll", commandType: CommandType.StoredProcedure);
            return result.ToList();
        }
        public void UpdateHome(Home home)
        {
            var p = new DynamicParameters();
            p.Add("p_id", home.Id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("home_title", home.Hometitle, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("home_content", home.Homecontent, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("home_image", home.Homeimage, dbType: DbType.String, direction: ParameterDirection.Input);

            _dbContext.Connection.Execute("home_page_pkg.UpdateHome", p, commandType: CommandType.StoredProcedure);
        }
    }
}
