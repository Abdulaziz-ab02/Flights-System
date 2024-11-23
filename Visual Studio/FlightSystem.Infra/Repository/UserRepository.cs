using Dapper;
using FlightSystem.Core.Common;
using FlightSystem.Core.DTO;
using FlightSystem.Core.Repository;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Repository
{
    public class UserRepository: IUserRepository
    {
        private readonly IDbContext _dbContext;
        public UserRepository(IDbContext dBContext)
        {
            _dbContext = dBContext;
        }


        public void CreateUser(UserDTO userDto)
        {
            var p = new DynamicParameters();

            // Add User table fields
            p.Add("p_FirstName", userDto.Firstname, DbType.String, ParameterDirection.Input);
            p.Add("p_LastName", userDto.Lastname, DbType.String, ParameterDirection.Input);
            p.Add("p_Email", userDto.Email, DbType.String, ParameterDirection.Input);
            p.Add("p_Phone", userDto.Phone, DbType.String, ParameterDirection.Input);
            p.Add("p_DateOfBirth", userDto.Dateofbirth, DbType.Date, ParameterDirection.Input);
            p.Add("p_Image", userDto.Image, DbType.String, ParameterDirection.Input);
            p.Add("p_NationalNumber", userDto.Nationalnumber, DbType.String, ParameterDirection.Input);

            // Add Login table fields
            p.Add("p_Username", userDto.Username, DbType.String, ParameterDirection.Input);
            p.Add("p_Password", userDto.Password, DbType.String, ParameterDirection.Input);
            p.Add("p_RoleId", userDto.Roleid, DbType.Int32, ParameterDirection.Input);

            _dbContext.Connection.Execute("USER_PKG.CreateUser", p, commandType: CommandType.StoredProcedure);
        }



        public void UpdateUser(UserDTO userDto)
        {
            if (userDto.Id == null)
            {
                throw new ArgumentException("UserId is required for update");
            }

            var p = new DynamicParameters();

            // Add User table fields
            p.Add("p_ID", userDto.Id, DbType.Int32, ParameterDirection.Input); // User ID for update
            p.Add("p_FirstName", userDto.Firstname, DbType.String, ParameterDirection.Input);
            p.Add("p_LastName", userDto.Lastname, DbType.String, ParameterDirection.Input);
            p.Add("p_Email", userDto.Email, DbType.String, ParameterDirection.Input);
            p.Add("p_Phone", userDto.Phone, DbType.String, ParameterDirection.Input);
            p.Add("p_DateOfBirth", userDto.Dateofbirth, DbType.Date, ParameterDirection.Input);
            p.Add("p_Image", userDto.Image, DbType.String, ParameterDirection.Input);
            p.Add("p_NationalNumber", userDto.Nationalnumber, DbType.String, ParameterDirection.Input);

            // Add Login table fields
            p.Add("p_Username", userDto.Username, DbType.String, ParameterDirection.Input);
            p.Add("p_Password", userDto.Password, DbType.String, ParameterDirection.Input);

            _dbContext.Connection.Execute("USER_PKG.UpdateUser", p, commandType: CommandType.StoredProcedure);
        }




        public List<UserDTO> GetAllUsers()
        {
            // Query the database to get all users
            return _dbContext.Connection.Query<UserDTO>("USER_PKG.GetAllUsers", commandType: CommandType.StoredProcedure).ToList();
        }

        public UserDTO GetUserById(int userId)
        {
            var p = new DynamicParameters();
            p.Add("U_ID", userId, dbType: DbType.Int32, direction: ParameterDirection.Input);

            // Query the database to get a single user by ID
            
         var res =_dbContext.Connection.Query<UserDTO>("USER_PKG.GetUserById", p, commandType: CommandType.StoredProcedure);


            return res.SingleOrDefault();


        }



        public string CheckUserExists(UserDTO user)
        {
            var p = new DynamicParameters();
            p.Add("p_Username", user.Username, dbType: DbType.String, direction: ParameterDirection.Input);
            p.Add("p_Email", user.Email, dbType: DbType.String, direction: ParameterDirection.Input);

            p.Add("p_Result", dbType: DbType.String, size: 20, direction: ParameterDirection.Output);

            var res = _dbContext.Connection.Execute("USER_PKG.CheckUserExists", p, commandType: CommandType.StoredProcedure);

            string result = p.Get<string>("p_Result");
            return result;
        }

        public List<UserDTO> GetUsersWithPartners()
        {
            var result = _dbContext.Connection.Query<UserDTO>("USER_PKG.GetUsersWithPartners", commandType: CommandType.StoredProcedure).ToList();
            return result.ToList();
        }

    }

}

