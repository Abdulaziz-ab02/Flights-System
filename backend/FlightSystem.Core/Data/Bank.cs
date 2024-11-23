using System;
using System.Collections.Generic;

namespace FlightSystem.Core.Data
{
    public partial class Bank
    {
        public decimal Id { get; set; }
        public decimal? Cardnumber { get; set; }
        public decimal? Cvv { get; set; }
        public DateTime? Expirydate { get; set; }
        public decimal? Balance { get; set; }
    }
}
