using FlightSystem.Core.Data;
using FlightSystem.Core.Repository;
using FlightSystem.Core.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Services
{
    public class BankService : IBankService
    {
        private readonly IBankRepository _bankRepository;
        public BankService(IBankRepository bankRepository)
        {
            _bankRepository = bankRepository;
        }
        public bool PaymentCheck(Bank bank)
        {
            return _bankRepository.PaymentCheck(bank);
        }

    }
}
