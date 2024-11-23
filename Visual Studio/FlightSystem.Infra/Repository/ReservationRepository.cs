using Dapper;
using FlightSystem.Core.Common;
using FlightSystem.Core.Data;
using FlightSystem.Core.DTO;
using FlightSystem.Core.Repository;
using Microsoft.Data.SqlClient;
using Oracle.ManagedDataAccess.Client;
using Oracle.ManagedDataAccess.Types;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Repository
{
    public class ReservationRepository :IReservationRepository
    {
        private readonly IDbContext _dbContext;
        public ReservationRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        public void CreateReservation(Reservation reservation)
        {
            var p = new DynamicParameters();
            p.Add("p_ReservationDate",reservation.Reservationdate,dbType:DbType.DateTime,direction:ParameterDirection.Input);
            p.Add("p_TotalPrice", reservation.Totalprice, dbType: DbType.Decimal, direction: ParameterDirection.Input);
            p.Add("p_NumOfPassengers", reservation.Numofpassengers, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_UserID", reservation.Userid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_FlightID", reservation.Flightid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            _dbContext.Connection.Execute("Reservation_Package.CreateReservation",p,commandType:CommandType.StoredProcedure);
        }

        public List<ReservationDTO> FetchReservationByUserID(int userId)
        {
            var p = new DynamicParameters();
            p.Add("p_UserID", userId, dbType:DbType.Int32,direction:ParameterDirection.Input);
            var result = _dbContext.Connection.Query<ReservationDTO>("Reservation_Package.FetchReservationsByUserID",
                p,  commandType:CommandType.StoredProcedure);
            return result.ToList();
        }


        public ReservationDTO FetchReservationById(int Id)
        {
            var p = new DynamicParameters();
            p.Add("p_id", Id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            var result = _dbContext.Connection.Query<ReservationDTO>("Reservation_Package.FetchReservationsByID",
                p, commandType: CommandType.StoredProcedure);
            return result.FirstOrDefault();
        }


        public List<ReservationDTO> FetchAllReservation()
        {
            var result = _dbContext.Connection.Query<ReservationDTO>("Reservation_Package.FetchAllReservations",
                 commandType: CommandType.StoredProcedure);
            return result.ToList();
        }

        

        public List<SearchReservationDTO> SearchReservation(SearchReservationDTO obj)
        {
            var p = new DynamicParameters();
            p.Add("fName", obj.Firstname, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("lName", obj.Lastname, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("flightNum", obj.Flightnumber, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("DateFrom", obj.DateFrom, dbType: DbType.DateTime, direction: ParameterDirection.Input);
            p.Add("DateTo", obj.DateTo, dbType: DbType.DateTime, direction: ParameterDirection.Input);

            var res = _dbContext.Connection.Query<SearchReservationDTO>("Reservation_Package.SearchReservation", p, commandType: CommandType.StoredProcedure);

            return res.ToList();
        }


    


        public CountDTO GetEntityCounts()
        {
            var counts = new CountDTO();

            var command = new OracleCommand("Reservation_Package.GetEntityCounts", (OracleConnection)_dbContext.Connection)
            {
                CommandType = CommandType.StoredProcedure
            };

            command.Parameters.Add("p_airports", OracleDbType.Int32, ParameterDirection.Output);
            command.Parameters.Add("p_users", OracleDbType.Int32, ParameterDirection.Output);
            command.Parameters.Add("p_reservations", OracleDbType.Int32, ParameterDirection.Output);
            command.Parameters.Add("p_airlines", OracleDbType.Int32, ParameterDirection.Output);

            command.ExecuteNonQuery();
            // Convert OracleDecimal to int
            counts.Airports = ((OracleDecimal)command.Parameters["p_airports"].Value).ToInt32();
            counts.Users = ((OracleDecimal)command.Parameters["p_users"].Value).ToInt32();
            counts.Reservations = ((OracleDecimal)command.Parameters["p_reservations"].Value).ToInt32();
            counts.Airlines = ((OracleDecimal)command.Parameters["p_airlines"].Value).ToInt32();

            return counts;
        }


        public decimal CalculateTotalBenefits(DateTime startDate, DateTime endDate)
        {
            var parameters = new DynamicParameters();
            parameters.Add("startDate", startDate, DbType.Date);
            parameters.Add("endDate", endDate, DbType.Date);
            parameters.Add("totalBenefits", dbType: DbType.Decimal, direction: ParameterDirection.Output);

            _dbContext.Connection.Execute("Reservation_Package.Calculate_Total_Benefits", parameters, commandType: CommandType.StoredProcedure);

            return parameters.Get<decimal>("totalBenefits");
        }



        public List<ReservationDTO> FetchReservationsByAirline(int airlineid)
        {
            var p = new DynamicParameters();
            p.Add("p_id", airlineid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            var result = _dbContext.Connection.Query<ReservationDTO>("Reservation_Package.FetchReservationsByAirline", p, commandType: CommandType.StoredProcedure);
            return result.ToList();
        }



        // Method to get the monthly benefits
        public List<ReservationDTO> GetMonthlyBenefits(int month, int year)
        {
            var p = new DynamicParameters();
            p.Add("reportMonth", month, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("reportYear ", year, dbType: DbType.Int32, direction: ParameterDirection.Input);

            // This assumes the procedure 'GetMonthlyBenefits' returns a list of reservations with total prices for the month
            var result = _dbContext.Connection.Query<ReservationDTO>("Reservation_Package. GetMonthlyReport",
                p, commandType: CommandType.StoredProcedure);

            return result.ToList();
        }

        // Method to get the annual benefits
        public List<ReservationDTO> GetAnnualBenefits(int year)
        {
            var p = new DynamicParameters();
            p.Add("reportYear", year, dbType: DbType.Int32, direction: ParameterDirection.Input);

            // This assumes the procedure 'GetAnnualBenefits' returns a list of reservations with total prices for the year
            var result = _dbContext.Connection.Query<ReservationDTO>("Reservation_Package.GetAnnualReport",
                p, commandType: CommandType.StoredProcedure);

            return result.ToList();
        }

    }
}
