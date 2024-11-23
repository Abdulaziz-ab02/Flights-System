using FlightSystem.Core.DTO;
using FlightSystem.Core.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EmailController : ControllerBase
    {
        private readonly IEmailService _emailService;
        private readonly IPdfService _pdfService;

        public EmailController(IEmailService emailService, IPdfService pdfService)
        {
            this._emailService = emailService;
            this._pdfService = pdfService;
        }

        [HttpPost]
        public async Task<IActionResult> SendFlightDetailsWithPdf([FromBody] InvoiceDTO flightDetails)
        {
            try
            {
                // Generate the PDF as a byte array
                byte[] pdfBytes = await _pdfService.GeneratePdfAsync(flightDetails);

                // Send the PDF as an email attachment
                var emailData = new EmailDataDTO
                {
                    ToEmail = flightDetails.Email,
                    Subject = "Your Flight Reservation Ticket",
                    Body = "Thank you for your reservation. Please find your flight ticket attached.",
                    Attachment = pdfBytes,
                    AttachmentName = "FlightTicket.pdf"
                };

                await _emailService.SendEmailAsync(emailData);

                return Ok("PDF generated and email sent successfully.");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }






    }
}
