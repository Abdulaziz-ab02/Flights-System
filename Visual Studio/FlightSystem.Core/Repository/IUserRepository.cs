using FlightSystem.Core.DTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Repository
{
    public interface IUserRepository
    {
        void CreateUser(UserDTO userDto);

        void UpdateUser(UserDTO userDto);

        List<UserDTO> GetAllUsers();
        UserDTO GetUserById(int userId);

        public string CheckUserExists(UserDTO user);

        public List<UserDTO> GetUsersWithPartners();
    }
}
