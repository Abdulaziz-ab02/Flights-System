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
    public class LoginRepository : ILoginRepository
    {
        private readonly IDbContext _dbContext;
        public LoginRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public Login Auth(Login login)
        {
            var p = new DynamicParameters();
            p.Add("user_name", login.Username, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("pass", login.Password, dbType: DbType.String, direction: ParameterDirection.Input);

            var res = _dbContext.Connection.Query<Login>("Login_Package.User_Login", p, commandType: System.Data.CommandType.StoredProcedure).FirstOrDefault();
            return res;
        }
        public AirlineLogin AirlineAuth(Login login)
        {
            var p = new DynamicParameters();
            p.Add("user_name",login.Username,dbType:DbType.String,direction:ParameterDirection.Input);
            p.Add("pass", login.Password, dbType: DbType.String, direction: ParameterDirection.Input);
            var res = _dbContext.Connection.Query<AirlineLogin>("Login_Package.Airline_Login",p,
                commandType:CommandType.StoredProcedure);
            return res.FirstOrDefault();

        }


    }
}
