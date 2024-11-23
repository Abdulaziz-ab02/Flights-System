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
    public class TestimonialRepository: ITestimonialRepository
    {
        private readonly IDbContext _dbContext;
        public TestimonialRepository(IDbContext dbContext)
        {
            _dbContext = dbContext;

        }

        public void CreateTestimonial(TestimonialDTO testimonial)
        {
            var p = new DynamicParameters();
            p.Add("T_content", testimonial.Testimonialcontent, DbType.String, ParameterDirection.Input);
            p.Add("T_rating", testimonial.Rating, DbType.Int32, ParameterDirection.Input);
            p.Add("T_date", testimonial.Testimonialdate, DbType.DateTime, ParameterDirection.Input);
            p.Add("T_status", testimonial.Testimonialstatus, DbType.String, ParameterDirection.Input);
            p.Add("User_id", testimonial.Userid, DbType.Int32, ParameterDirection.Input);

            _dbContext.Connection.Execute("TESTIMONIALS_PKG.CREATE_TESTIMONIAL", p, commandType: CommandType.StoredProcedure);
        }


        public void DeleteTestimonial(int testimonialId)
        {
            var p = new DynamicParameters();
            p.Add("T_id", testimonialId, DbType.Int32, ParameterDirection.Input);

            _dbContext.Connection.Execute("TESTIMONIALS_PKG.DELETE_TESTIMONIAL", p, commandType: CommandType.StoredProcedure);
        }

        public List<TestimonialDTO> GetAllTestimonials()
        {
            return _dbContext.Connection.Query<TestimonialDTO>("TESTIMONIALS_PKG.GET_ALL_TESTIMONIALS", commandType: CommandType.StoredProcedure).ToList();
        }


        public void ChangeTestimonialStatus(int testimonialId, string status)
        {
            var p = new DynamicParameters();
            p.Add("T_id", testimonialId, DbType.Int32, ParameterDirection.Input);
            p.Add("T_status", status, DbType.String, ParameterDirection.Input);

            _dbContext.Connection.Execute("TESTIMONIALS_PKG.CHANGE_TESTIMONIAL_STATUS", p, commandType: CommandType.StoredProcedure);
        }




    }
}
