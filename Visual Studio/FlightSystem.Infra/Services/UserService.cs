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
    public class UserService: IUserService
    {
        private readonly IUserRepository _userRepository;

        // Constructor Injection
        public UserService(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }

        public void CreateUser(UserDTO userDto)
        {
            _userRepository.CreateUser(userDto);
        }   

        public void UpdateUser(UserDTO userDto)
        {
            if (userDto.Id == null)
            {
                throw new ArgumentException("UserId is required for update");
            }

            // Perform any business logic (e.g., checking if the user exists, etc.)
           /*var existingUser = _userRepository.GetUserById(Convert.ToInt32(userDto.Id.Value));
            if (existingUser == null)
            {
                throw new Exception("User not found");
            }
          */
            // Call the repository to update the user
            _userRepository.UpdateUser(userDto);
        }


        public List<UserDTO> GetAllUsers()
        {
            // Call repository to get all users
            return _userRepository.GetAllUsers();
        }

        public UserDTO GetUserById(int userId)
        {
            // Call repository to get a user by ID
            return _userRepository.GetUserById(userId);
        }

        public string CheckUserExists(UserDTO user)
        {
            return _userRepository.CheckUserExists(user);
        }

        public List<UserDTO> GetUsersWithPartners()
        {
            return _userRepository.GetUsersWithPartners();
        }


    }
}
