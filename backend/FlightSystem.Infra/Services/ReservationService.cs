using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using FlightSystem.Core.Repository;
using FlightSystem.Core.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Services
{
    public class ReservationService : IReservationService
    {
        private readonly IReservationRepository _reservationRepository;
        public ReservationService(IReservationRepository reservationRepository)
        {
            _reservationRepository = reservationRepository;
        }
        public void CreateReservation(Reservation reservation)
        {
            _reservationRepository.CreateReservation(reservation);
        }
        public ReservationDTO FetchReservationById(int id)
        {
            return _reservationRepository.FetchReservationById(id);
        }
        public List<ReservationDTO> FetchAllReservation()
        {
            return _reservationRepository.FetchAllReservation();
        }
        public List<ReservationDTO> FetchReservationByUserID(int userId)
        {
            return _reservationRepository.FetchReservationByUserID(userId);
        }

        public List<SearchReservationDTO> SearchReservation(SearchReservationDTO obj)
        {
            return _reservationRepository.SearchReservation(obj);
        }


     
        public CountDTO GetEntityCounts()
        {

        return _reservationRepository.GetEntityCounts(); 
        }

        public decimal CalculateTotalBenefits(DateTime startDate, DateTime endDate)
        {
            return _reservationRepository.CalculateTotalBenefits(startDate, endDate);
        }


        public List<ReservationDTO> FetchReservationsByAirline(int airlineid)
        {
            return _reservationRepository.FetchReservationsByAirline(airlineid);
        }

        public List<ReservationDTO> GetMonthlyBenefits(int month, int year)
        {
            return _reservationRepository.GetMonthlyBenefits(month, year);
        }

        public List<ReservationDTO> GetAnnualBenefits(int year)
        {
            return _reservationRepository.GetAnnualBenefits(year);
        }

    }
}
