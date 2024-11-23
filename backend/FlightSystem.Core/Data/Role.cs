using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class Role
    {
        public Role()
        {
            Logins = new HashSet<Login>();
        }

        public decimal Id { get; set; }
        public string? Rolename { get; set; }

        public virtual ICollection<Login> Logins { get; set; }
    }
}
