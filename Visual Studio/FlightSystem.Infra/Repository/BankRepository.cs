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
    public class BankRepository : IBankRepository
    {
        private readonly IDbContext _dbContext;
        public BankRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        public bool PaymentCheck(Bank bank)
        {
            var p = new DynamicParameters();
            p.Add("p_CardNumber", bank.Cardnumber, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_CVV", bank.Cvv, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_ExpiryDate", bank.Expirydate, dbType: DbType.DateTime, direction: ParameterDirection.Input);
            p.Add("p_Balance", bank.Balance, dbType: DbType.Decimal, direction: ParameterDirection.Input);
            p.Add("p_Result", bank.Balance, dbType: DbType.Boolean, direction: ParameterDirection.Output);

            _dbContext.Connection.Execute("BANK_PACKAGE.PaymentCheck",p,commandType:CommandType.StoredProcedure);
            bool result = p.Get<bool>("p_Result");
            return result;
        }
    }
}
