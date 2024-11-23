using FlightSystem.Core.DTO;
using FlightSystem.Core.Repository;
using FlightSystem.Core.Services;
using FlightSystem.Infra.Repository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FlightSystem.Infra.Services
{
    public class TestimonialService: ITestimonialService
    {
        private readonly ITestimonialRepository _testimonialRepository;

        public TestimonialService(ITestimonialRepository testimonialRepository)
        {
            _testimonialRepository = testimonialRepository;
        }

        public void CreateTestimonial(TestimonialDTO testimonial)
        {
            _testimonialRepository.CreateTestimonial(testimonial);
        }

        public void DeleteTestimonial(int id)
        {
            _testimonialRepository.DeleteTestimonial(id);
        }

        public List<TestimonialDTO> GetAllTestimonials()
        {
            return _testimonialRepository.GetAllTestimonials();
        }

        public void ChangeTestimonialStatus(int id, string status)
        {
            _testimonialRepository.ChangeTestimonialStatus(id, status);
        }
    }
}
