using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace FlightSystem.Core.Data
{
    public partial class ModelContext : DbContext
    {
        public ModelContext()
        {
        }

        public ModelContext(DbContextOptions<ModelContext> options)
            : base(options)
        {
        }

        public virtual DbSet<Aboutu> Aboutus { get; set; } = null!;
        public virtual DbSet<Airline> Airlines { get; set; } = null!;
        public virtual DbSet<Airport> Airports { get; set; } = null!;
        public virtual DbSet<Bank> Banks { get; set; } = null!;
        public virtual DbSet<City> Cities { get; set; } = null!;
        public virtual DbSet<Contactu> Contactus { get; set; } = null!;
        public virtual DbSet<Country> Countries { get; set; } = null!;
        public virtual DbSet<Degree> Degrees { get; set; } = null!;
        public virtual DbSet<DegreeFacility> DegreeFacilities { get; set; } = null!;
        public virtual DbSet<Facility> Facilities { get; set; } = null!;
        public virtual DbSet<Flight> Flights { get; set; } = null!;
        public virtual DbSet<Home> Homes { get; set; } = null!;
        public virtual DbSet<Login> Logins { get; set; } = null!;
        public virtual DbSet<Partner> Partners { get; set; } = null!;
        public virtual DbSet<Reservation> Reservations { get; set; } = null!;
        public virtual DbSet<Role> Roles { get; set; } = null!;
        public virtual DbSet<Testimonial> Testimonials { get; set; } = null!;
        public virtual DbSet<User> Users { get; set; } = null!;
        public virtual DbSet<ContactMessage> ContactMessages { get; set; } = null!;

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see http://go.microsoft.com/fwlink/?LinkId=723263.
                optionsBuilder.UseOracle("User Id=C##Yara4;PASSWORD=Test321;DATA SOURCE=localhost:1521/xe");
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.HasDefaultSchema("C##Final")
                .UseCollation("USING_NLS_COMP");

            modelBuilder.Entity<Aboutu>(entity =>
            {
                entity.ToTable("ABOUTUS");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Aboutcontent)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("ABOUTCONTENT");

                entity.Property(e => e.Aboutimage)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("ABOUTIMAGE");

                entity.Property(e => e.Abouttitle)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("ABOUTTITLE");
            });

            modelBuilder.Entity<Airline>(entity =>
            {
                entity.ToTable("AIRLINES");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Activationstatus)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("ACTIVATIONSTATUS");

                entity.Property(e => e.Airlineaddress)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("AIRLINEADDRESS");

                entity.Property(e => e.Airlineemail)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("AIRLINEEMAIL");

                entity.Property(e => e.Airlineimage)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("AIRLINEIMAGE");

                entity.Property(e => e.Airlinename)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("AIRLINENAME");
            });

            modelBuilder.Entity<Airport>(entity =>
            {
                entity.ToTable("AIRPORT");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Airportimage)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("AIRPORTIMAGE");

                entity.Property(e => e.Airportname)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("AIRPORTNAME");

                entity.Property(e => e.Cityid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("CITYID");

                entity.Property(e => e.Iatacode)
                    .HasMaxLength(10)
                    .IsUnicode(false)
                    .HasColumnName("IATACODE");

                entity.Property(e => e.Latitude)
                    .HasColumnType("NUMBER")
                    .HasColumnName("LATITUDE");

                entity.Property(e => e.Longitude)
                    .HasColumnType("NUMBER")
                    .HasColumnName("LONGITUDE");

                entity.HasOne(d => d.City)
                    .WithMany(p => p.Airports)
                    .HasForeignKey(d => d.Cityid)
                    .OnDelete(DeleteBehavior.Cascade)
                    .HasConstraintName("SYS_C008453");
            });

            modelBuilder.Entity<Bank>(entity =>
            {
                entity.ToTable("BANK");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Balance)
                    .HasColumnType("NUMBER")
                    .HasColumnName("BALANCE");

                entity.Property(e => e.Cardnumber).
                HasColumnType("NUMBER")
                    .IsUnicode(false)
                    .HasColumnName("CARDNUMBER");

                entity.Property(e => e.Cvv)
                    .HasColumnType("NUMBER")
                    .IsUnicode(false)
                    .HasColumnName("CVV");

                entity.Property(e => e.Expirydate)
                    .HasColumnType("DATE")
                    .HasColumnName("EXPIRYDATE");
            });

            modelBuilder.Entity<City>(entity =>
            {
                entity.ToTable("CITY");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Cityname)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("CITYNAME");

                entity.Property(e => e.Countryid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("COUNTRYID");

                entity.Property(e => e.Cityimage)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("CITYIMAGE");

                entity.HasOne(d => d.Country)
                    .WithMany(p => p.Cities)
                    .HasForeignKey(d => d.Countryid)
                    .OnDelete(DeleteBehavior.Cascade)
                    .HasConstraintName("SYS_C008450");
            });

            modelBuilder.Entity<Contactu>(entity =>
            {
                entity.ToTable("CONTACTUS");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Contactemail)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("CONTACTEMAIL");

                entity.Property(e => e.Contactphone)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("CONTACTPHONE");

                entity.Property(e => e.Contactaddress)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("CONTACTADDRESS");
            });

            modelBuilder.Entity<Country>(entity =>
            {
                entity.ToTable("COUNTRY");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Countryname)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("COUNTRYNAME");
            });

            modelBuilder.Entity<Degree>(entity =>
            {
                entity.ToTable("DEGREE");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Degreename)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("DEGREENAME");
            });

            modelBuilder.Entity<DegreeFacility>(entity =>
            {
                entity.ToTable("DEGREE_FACILITIES");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Degreeid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("DEGREEID");

                entity.Property(e => e.Facilityid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("FACILITYID");

                entity.HasOne(d => d.Degree)
                    .WithMany(p => p.DegreeFacilities)
                    .HasForeignKey(d => d.Degreeid)
                    .OnDelete(DeleteBehavior.Cascade)
                    .HasConstraintName("SYS_C008471");

                entity.HasOne(d => d.Facility)
                    .WithMany(p => p.DegreeFacilities)
                    .HasForeignKey(d => d.Facilityid)
                    .OnDelete(DeleteBehavior.Cascade)
                    .HasConstraintName("SYS_C008472");
            });

            modelBuilder.Entity<Facility>(entity =>
            {
                entity.ToTable("FACILITY");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Facilityimage)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("FACILITYIMAGE");

                entity.Property(e => e.Facilityname)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("FACILITYNAME");
            });

            modelBuilder.Entity<Flight>(entity =>
            {
                entity.ToTable("FLIGHT");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Airlineid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("AIRLINEID");

                entity.Property(e => e.Capacity)
                    .HasColumnType("NUMBER")
                    .HasColumnName("CAPACITY");

                entity.Property(e => e.Degreeid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("DEGREEID");

                entity.Property(e => e.Departureairportid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("DEPARTUREAIRPORTID");

                entity.Property(e => e.Departuredate)
                    .HasColumnType("DATE")
                    .HasColumnName("DEPARTUREDATE");

                entity.Property(e => e.Destinationairportid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("DESTINATIONAIRPORTID");

                entity.Property(e => e.Destinationdate)
                    .HasColumnType("DATE")
                    .HasColumnName("DESTINATIONDATE");

                entity.Property(e => e.Discountvalue)
                    .HasColumnType("NUMBER")
                    .HasColumnName("DISCOUNTVALUE");

                entity.Property(e => e.Flightnumber)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("FLIGHTNUMBER");

                entity.Property(e => e.Priceperpassenger)
                    .HasColumnType("NUMBER")
                    .HasColumnName("PRICEPERPASSENGER");

                entity.Property(e => e.Status)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("STATUS");

                entity.HasOne(d => d.Airline)
                    .WithMany(p => p.Flights)
                    .HasForeignKey(d => d.Airlineid)
                    .OnDelete(DeleteBehavior.Cascade)
                    .HasConstraintName("SYS_C008491");

                entity.HasOne(d => d.Degree)
                    .WithMany(p => p.Flights)
                    .HasForeignKey(d => d.Degreeid)
                    .OnDelete(DeleteBehavior.SetNull)
                    .HasConstraintName("SYS_C008494");

                entity.HasOne(d => d.Departureairport)
                    .WithMany(p => p.FlightDepartureairports)
                    .HasForeignKey(d => d.Departureairportid)
                    .OnDelete(DeleteBehavior.Cascade)
                    .HasConstraintName("SYS_C008492");

                entity.HasOne(d => d.Destinationairport)
                    .WithMany(p => p.FlightDestinationairports)
                    .HasForeignKey(d => d.Destinationairportid)
                    .OnDelete(DeleteBehavior.Cascade)
                    .HasConstraintName("SYS_C008493");
                entity.Property(e => e.PriceAfterDiscount)
                   .HasColumnType("NUMBER")
                   .HasColumnName("PRICEAFTERDISCOUNT");
            });

            modelBuilder.Entity<Home>(entity =>
            {
                entity.ToTable("HOME");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Homecontent)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("HOMECONTENT");

                entity.Property(e => e.Homeimage)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("HOMEIMAGE");

                entity.Property(e => e.Hometitle)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("HOMETITLE");
            });

            modelBuilder.Entity<Login>(entity =>
            {
                entity.ToTable("LOGIN");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Airlineid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("AIRLINEID");

                entity.Property(e => e.Password)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("PASSWORD");

                entity.Property(e => e.Roleid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("ROLEID");

                entity.Property(e => e.Userid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("USERID");

                entity.Property(e => e.Username)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("USERNAME");

                entity.HasOne(d => d.Airline)
                    .WithMany(p => p.Logins)
                    .HasForeignKey(d => d.Airlineid)
                    .OnDelete(DeleteBehavior.SetNull)
                    .HasConstraintName("SYS_C008501");

                entity.HasOne(d => d.Role)
                    .WithMany(p => p.Logins)
                    .HasForeignKey(d => d.Roleid)
                    .OnDelete(DeleteBehavior.SetNull)
                    .HasConstraintName("SYS_C008460");

                entity.HasOne(d => d.User)
                    .WithMany(p => p.Logins)
                    .HasForeignKey(d => d.Userid)
                    .OnDelete(DeleteBehavior.SetNull)
                    .HasConstraintName("SYS_C008461");
            });

            modelBuilder.Entity<Partner>(entity =>
            {
                entity.ToTable("PARTNER");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Firstname)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("FIRSTNAME");

                entity.Property(e => e.Lastname)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("LASTNAME");

                entity.Property(e => e.Nationalnumber)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("NATIONALNUMBER");

                entity.Property(e => e.Userid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("USERID");

                entity.HasOne(d => d.User)
                    .WithMany(p => p.Partners)
                    .HasForeignKey(d => d.Userid)
                    .OnDelete(DeleteBehavior.SetNull)
                    .HasConstraintName("SYS_C008479");
            });

            modelBuilder.Entity<Reservation>(entity =>
            {
                entity.ToTable("RESERVATION");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Flightid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("FLIGHTID");

                entity.Property(e => e.Numofpassengers)
                    .HasColumnType("NUMBER")
                    .HasColumnName("NUMOFPASSENGERS");

                entity.Property(e => e.Reservationdate)
                    .HasColumnType("DATE")
                    .HasColumnName("RESERVATIONDATE");

                entity.Property(e => e.Totalprice)
                    .HasColumnType("NUMBER")
                    .HasColumnName("TOTALPRICE");

                entity.Property(e => e.Userid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("USERID");

                entity.HasOne(d => d.Flight)
                    .WithMany(p => p.Reservations)
                    .HasForeignKey(d => d.Flightid)
                    .OnDelete(DeleteBehavior.Cascade)
                    .HasConstraintName("SYS_C008498");

                entity.HasOne(d => d.User)
                    .WithMany(p => p.Reservations)
                    .HasForeignKey(d => d.Userid)
                    .OnDelete(DeleteBehavior.SetNull)
                    .HasConstraintName("SYS_C008497");
            });

            modelBuilder.Entity<Role>(entity =>
            {
                entity.ToTable("ROLE");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Rolename)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("ROLENAME");
            });

            modelBuilder.Entity<Testimonial>(entity =>
            {
                entity.ToTable("TESTIMONIAL");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Rating)
                    .HasColumnType("NUMBER")
                    .HasColumnName("RATING");

                entity.Property(e => e.Testimonialcontent)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("TESTIMONIALCONTENT");

                entity.Property(e => e.Testimonialdate)
                    .HasColumnType("DATE")
                    .HasColumnName("TESTIMONIALDATE");

                entity.Property(e => e.Testimonialstatus)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("TESTIMONIALSTATUS");

                entity.Property(e => e.Userid)
                    .HasColumnType("NUMBER")
                    .HasColumnName("USERID");

                entity.HasOne(d => d.User)
                    .WithMany(p => p.Testimonials)
                    .HasForeignKey(d => d.Userid)
                    .OnDelete(DeleteBehavior.SetNull)
                    .HasConstraintName("SYS_C008476");
            });

            modelBuilder.Entity<User>(entity =>
            {
                entity.ToTable("USERS");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Dateofbirth)
                    .HasColumnType("DATE")
                    .HasColumnName("DATEOFBIRTH");

                entity.Property(e => e.Email)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("EMAIL");

                entity.Property(e => e.Firstname)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("FIRSTNAME");

                entity.Property(e => e.Image)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("IMAGE");

                entity.Property(e => e.Lastname)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("LASTNAME");

                entity.Property(e => e.Nationalnumber)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("NATIONALNUMBER");

                entity.Property(e => e.Phone)
                    .HasMaxLength(50)
                    .IsUnicode(false)
                    .HasColumnName("PHONE");
            });



            modelBuilder.Entity<ContactMessage>(entity =>
            {
                entity.ToTable("CONTACT_MESSAGES");

                entity.Property(e => e.Id)
                    .HasColumnType("NUMBER")
                    .ValueGeneratedOnAdd()
                    .HasColumnName("ID");

                entity.Property(e => e.Firstname)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("FIRSTNAME");

                entity.Property(e => e.Lastname)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("LASTNAME");

                entity.Property(e => e.Email)
                    .HasMaxLength(255)
                    .IsUnicode(false)
                    .HasColumnName("EMAIL");

                entity.Property(e => e.Message)
                    .HasColumnType("CLOB")
                    .HasColumnName("MESSAGE");
            });




            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}
