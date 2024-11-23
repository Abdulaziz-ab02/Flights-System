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
    public class FlightRepository : IFlightRepository
    {
        private readonly IDbContext _dbContext;
        public FlightRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        
        public void CreateFlight(Flight flight)
        {
            var p = new DynamicParameters();
            p.Add("p_FlightNumber", flight.Flightnumber, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("p_Capacity", flight.Capacity, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_price", flight.Priceperpassenger, dbType: DbType.Decimal, direction: ParameterDirection.Input);
            p.Add("p_Departure_Date", flight.Departuredate, dbType: DbType.DateTime, direction: ParameterDirection.Input);
            p.Add("p_Destination_Date", flight.Destinationdate, dbType: DbType.DateTime, direction: ParameterDirection.Input);
            p.Add("p_DiscountValue", flight.Discountvalue, dbType: DbType.Decimal, direction: ParameterDirection.Input);
            p.Add("p_AirLineID", flight.Airlineid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_DepartureAirportID", flight.Departureairportid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_DestinationAirportID", flight.Destinationairportid, dbType: DbType.Decimal, direction: ParameterDirection.Input);
            p.Add("p_DegreeID", flight.Degreeid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_PriceAfterDiscount", flight.PriceAfterDiscount, dbType: DbType.Int32, direction: ParameterDirection.Input);

            _dbContext.Connection.Execute("Flight_Package.CreateFlight", p, commandType: CommandType.StoredProcedure);
        }
        public void UpdateFlight(Flight flight)
        {
            var p = new DynamicParameters();
            p.Add("p_ID", flight.Id, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_FlightNumber", flight.Flightnumber, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("p_Capacity", flight.Capacity, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_price", flight.Priceperpassenger, dbType: DbType.Decimal, direction: ParameterDirection.Input);
            p.Add("p_Departure_Date", flight.Departuredate, dbType: DbType.DateTime, direction: ParameterDirection.Input);
            p.Add("p_Destination_Date", flight.Destinationdate, dbType: DbType.DateTime, direction: ParameterDirection.Input);
            p.Add("p_DiscountValue", flight.Discountvalue, dbType: DbType.Decimal, direction: ParameterDirection.Input);
            p.Add("p_AirLineID", flight.Airlineid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_DepartureAirportID", flight.Departureairportid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_DestinationAirportID", flight.Destinationairportid, dbType: DbType.Decimal, direction: ParameterDirection.Input);
            p.Add("p_DegreeID", flight.Degreeid, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_PriceAfterDiscount", flight.PriceAfterDiscount, dbType: DbType.Int32, direction: ParameterDirection.Input);

            _dbContext.Connection.Execute("Flight_Package.UpdateFlight", p, commandType: CommandType.StoredProcedure);
        }
        public void DeleteFlight(int id)
        {
            var p = new DynamicParameters();
            p.Add("p_ID",id,dbType:DbType.Int32,direction:ParameterDirection.Input);
            _dbContext.Connection.Execute("Flight_Package.DeleteFlight",p,commandType:CommandType.StoredProcedure);
        }
        public FlightDTO FetchFlightByID(int id)
        {
            var p = new DynamicParameters();
            p.Add("p_ID",id,dbType:DbType.Int32,direction:ParameterDirection.Input);
            var result = _dbContext.Connection.Query<FlightDTO>("Flight_Package.FetchFlightByID",p,
                commandType:CommandType.StoredProcedure);
            return result.FirstOrDefault();
        }
        public FlightDTO FetchFlightByFlightNumber(string flightNumber)
        {
            var p = new DynamicParameters();
            p.Add("p_FlightNumber", flightNumber,dbType: DbType.String,direction:ParameterDirection.Input);
            var result = _dbContext.Connection.Query<FlightDTO>("Flight_Package.FetchFlightByFlightNumber",p,
                commandType:CommandType.StoredProcedure);
            return result.SingleOrDefault();
        }
        public List<FlightDTO> FetchAllFlights()
        {
            var result = _dbContext.Connection.Query<FlightDTO>("Flight_Package.FetchAllFlights",
                commandType: CommandType.StoredProcedure);
            return result.ToList();
        }
        public List<ReturnFlightSearch> FetchFlightBasedOnUserSearch(FlightForSearchDTO obj)
        {
            var p = new DynamicParameters();
            p.Add("p_DepartureCityID", obj.DeparturePlaceId, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_DestinationCityID", obj.DestenationPlaceId, dbType: DbType.Int32, direction: ParameterDirection.Input);
            p.Add("p_DepartureDate", obj.Departuredate, dbType: DbType.Date, direction: ParameterDirection.Input);
            p.Add("p_ClassTypeID", obj.DegreenameId, dbType: DbType.Int32, direction: ParameterDirection.Input);

            var result = _dbContext.Connection.Query<ReturnFlightSearch>("Flight_Package.SearchForFlights",p, commandType: CommandType.StoredProcedure);
            return result.ToList();
        }
        public List<DfDTO> GetAllFacilitesByDegreeId(int id)
        {
            var p = new DynamicParameters();
            p.Add("p_Degreeid",id,dbType:DbType.Int32,direction:ParameterDirection.Input);
            var result = _dbContext.Connection.Query<DfDTO>("Flight_Package.FetchAllFacilitesByDegreeId",p,
                commandType:CommandType.StoredProcedure);
            return result.ToList();
        }

        public List<FlightDTO> GetAllFlightsByAirlineID(int airlineId)
        {
            var p = new DynamicParameters();
            p.Add("p_AirlineID", airlineId, dbType: DbType.Int32, direction: ParameterDirection.Input);
            var result = _dbContext.Connection.Query<FlightDTO>("Flight_Package.GetAllFlightsByAirlineID", p, commandType: CommandType.StoredProcedure);
            return result.ToList();
        }


    }
}
