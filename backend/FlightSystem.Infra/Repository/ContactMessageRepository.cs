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
    public class ContactMessageRepository : IContactMessageRepository
    {
        private readonly IDbContext _dbContext;
        public ContactMessageRepository(IDbContext dBContext)
        {
            _dbContext = dBContext;
        }

        public List<ContactMessage> GetAllContactMessages()
        {

            var result = _dbContext.Connection.Query<ContactMessage>("contactMessage_pkg.GetAll", commandType: CommandType.StoredProcedure);
            return result.ToList();
        }

        public void CreateContactMessage(ContactMessage message)
        {
            var p = new DynamicParameters();

            p.Add("p_FirstName", message.Firstname, DbType.String, ParameterDirection.Input);
            p.Add("p_LastName", message.Lastname, DbType.String, ParameterDirection.Input);
            p.Add("p_Email", message.Email, DbType.String, ParameterDirection.Input);
            p.Add("p_message", message.Message, DbType.String, ParameterDirection.Input);

            _dbContext.Connection.Execute("contactMessage_pkg.CreateContactMessage", p, commandType: CommandType.StoredProcedure);
        }


    }
}
