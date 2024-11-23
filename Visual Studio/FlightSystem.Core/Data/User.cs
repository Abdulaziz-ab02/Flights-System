using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class User
    {
        public User()
        {
            Logins = new HashSet<Login>();
            Partners = new HashSet<Partner>();
            Reservations = new HashSet<Reservation>();
            Testimonials = new HashSet<Testimonial>();
        }

        public decimal Id { get; set; }
        public string? Firstname { get; set; }
        public string? Lastname { get; set; }
        public string? Email { get; set; }
        public string? Phone { get; set; }
        public DateTime? Dateofbirth { get; set; }
        public string? Image { get; set; }
        public string? Nationalnumber { get; set; }

        public virtual ICollection<Login> Logins { get; set; }
        public virtual ICollection<Partner> Partners { get; set; }
        public virtual ICollection<Reservation> Reservations { get; set; }
        public virtual ICollection<Testimonial> Testimonials { get; set; }
    }
}
