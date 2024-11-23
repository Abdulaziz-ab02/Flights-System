using FlightSystem.Core.DTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Core.Repository
{
    public interface ITestimonialRepository
    {
        void CreateTestimonial(TestimonialDTO testimonial);

        void DeleteTestimonial(int testimonialId);

        List<TestimonialDTO> GetAllTestimonials();

        void ChangeTestimonialStatus(int testimonialId, string status);
    }
}
