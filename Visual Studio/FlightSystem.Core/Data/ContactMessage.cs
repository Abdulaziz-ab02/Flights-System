using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class ContactMessage
    {
        public int Id { get; set; }
        public string? Firstname { get; set; }
        public string? Lastname { get; set; }
        public string? Email { get; set; }
        public string? Message { get; set; }
    }
}
