using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.DTO
{
    public class UserDTO
    {
        public string? Firstname { get; set; }
        public string? Lastname { get; set; }
        public string? Email { get; set; }
        public string? Phone { get; set; }
        public DateTime? Dateofbirth { get; set; }
        public string? Image { get; set; }
        public string? Nationalnumber { get; set; }


       
        //Login 
        public string? Username { get; set; }
        public string? Password { get; set; }
        public decimal? Roleid { get; set; }


        // For Update purposes, the User ID can be optional
        public decimal? Id { get; set; }  // Nullable, only needed for update

    }
}
