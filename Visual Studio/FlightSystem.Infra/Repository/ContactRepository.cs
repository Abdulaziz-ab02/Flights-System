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
    public class ContactRepository : IContactRepository
    {
        private readonly IDbContext _dbContext;
        public ContactRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public List<Contactu> GetAll()
        {
            var result = _dbContext.Connection.Query<Contactu>("contact_pkg.GetAll", commandType: CommandType.StoredProcedure);
            return result.ToList();
        }
        public void UpdateContact(Contactu contact)
        {

            var p = new DynamicParameters();
            p.Add("p_id", contact.Id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("contact_email", contact.Contactemail, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("contact_phone", contact.Contactphone, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("contact_address", contact.Contactaddress, dbType: DbType.String, direction: ParameterDirection.Input);

            _dbContext.Connection.Execute("contact_pkg.UpdateContact", p, commandType: CommandType.StoredProcedure);
        }
    }
}
