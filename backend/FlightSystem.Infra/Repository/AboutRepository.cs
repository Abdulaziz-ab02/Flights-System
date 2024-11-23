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
    public class AboutRepository : IAboutRepository
    {
        private readonly IDbContext _dbContext;
        public AboutRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public List<Aboutu> GetAll()
        {
            var result = _dbContext.Connection.Query<Aboutu>("about_pkg.GetAll", commandType: CommandType.StoredProcedure);
            return result.ToList();
        }
        public void UpdateAbout(Aboutu aboutus)
        {
            var p = new DynamicParameters();
            p.Add("p_id", aboutus.Id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("about_title", aboutus.Abouttitle, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("about_content", aboutus.Aboutcontent, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("about_image", aboutus.Aboutimage, dbType: DbType.String, direction: ParameterDirection.Input);

            _dbContext.Connection.Execute("about_pkg.UpdateAbout", p, commandType: CommandType.StoredProcedure);
        }
    }
}
