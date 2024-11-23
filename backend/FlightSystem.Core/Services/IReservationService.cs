using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Services
{
    public interface IReservationService
    {
        public void CreateReservation(Reservation reservation);
        public ReservationDTO FetchReservationById(int id);
        public List<ReservationDTO> FetchAllReservation();
        public List<ReservationDTO> FetchReservationByUserID(int userId);

        public List<SearchReservationDTO> SearchReservation(SearchReservationDTO obj);

       
        public CountDTO GetEntityCounts();

        public decimal CalculateTotalBenefits(DateTime startDate, DateTime endDate);

        public List<ReservationDTO> FetchReservationsByAirline(int airlineid);

        public List<ReservationDTO> GetMonthlyBenefits(int month, int year);

        public List<ReservationDTO> GetAnnualBenefits(int year);

    }
}
