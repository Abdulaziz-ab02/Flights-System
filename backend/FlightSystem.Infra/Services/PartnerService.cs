using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using FlightSystem.Core.Repository;
using FlightSystem.Core.Services;
using FlightSystem.Infra.Repository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Services
{
    public class PartnerService: IPartnerService
    {
        private readonly IPartnerRepository _partnerRepository;

        // Constructor Injection
        public PartnerService(IPartnerRepository partnerRepository)
        {
            _partnerRepository = partnerRepository;
        }


        public void CreatePartner(Partner partner)
        {
            _partnerRepository.CreatePartner(partner);
        }

        public List<PartnerDTO> GetPartnersByUser(int userId)
        {
            return _partnerRepository.GetPartnersByUser(userId);
        }

    }
}
