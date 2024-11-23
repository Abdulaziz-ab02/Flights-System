using Dapper;
using FlightSystem.Core.Common;
using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using FlightSystem.Core.Repository;
using Oracle.ManagedDataAccess.Client;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Repository
{
    public class PartnerRepository: IPartnerRepository
    {
        private readonly IDbContext _dbContext;
        public PartnerRepository(IDbContext dBContext)
        {
            _dbContext = dBContext;
        }




        public void CreatePartner(Partner partner)
        {
            var p = new DynamicParameters();
            p.Add("F_NAME", partner.Firstname, DbType.String, ParameterDirection.Input);
            p.Add("L_NAME", partner.Lastname, DbType.String, ParameterDirection.Input);
            p.Add("NATIONAL_NUM", partner.Nationalnumber, DbType.String, ParameterDirection.Input);
            p.Add("U_ID", partner.Userid, DbType.Int32, ParameterDirection.Input);

            _dbContext.Connection.Execute("PARTENER_PKG.CreatePartner", p, commandType: CommandType.StoredProcedure);
        }

        public List<PartnerDTO> GetPartnersByUser(int userId)
        {
            var p = new DynamicParameters();
            p.Add("p_UserId", userId, DbType.Int32, ParameterDirection.Input);

         return _dbContext.Connection.Query<PartnerDTO>("PARTENER_PKG.GetPartnersByUser",p,commandType: CommandType.StoredProcedure).ToList();


        }

    }
}
