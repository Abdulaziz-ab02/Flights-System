using FlightSystem.Core.DTO;
using FlightSystem.Core.Services;
using FlightSystem.Infra;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Net.Mail;
using System.Net;

public class EmailService : IEmailService
{
    private readonly SmtpSettings _smtpSettings;
    private readonly ILogger<EmailService> _logger;

    public EmailService(IOptions<SmtpSettings> smtpSettings, ILogger<EmailService> logger)
    {
        _smtpSettings = smtpSettings.Value;
        _logger = logger;
    }

    public async Task SendEmailAsync(EmailDataDTO emailData)
    {
        try
        {
            using var client = new SmtpClient
            {
                Host = _smtpSettings.SmtpServer,
                Port = _smtpSettings.SmtpPort,
                EnableSsl = _smtpSettings.UseSsl,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(_smtpSettings.Username, _smtpSettings.Password),
                DeliveryMethod = SmtpDeliveryMethod.Network,
                Timeout = 30000 // 30 seconds timeout
            };

            using var mailMessage = new MailMessage
            {
                From = new MailAddress(_smtpSettings.FromAddress),
                Subject = emailData.Subject,
                Body = emailData.Body,
                IsBodyHtml = true
            };

            mailMessage.To.Add(emailData.ToEmail);

            // Handle attachments if any
            if (emailData.Attachment != null && emailData.Attachment.Length > 0)
            {
                var ms = new MemoryStream(emailData.Attachment);
                ms.Position = 0;  // Ensure the stream is at the beginning
                var attachment = new Attachment(ms, emailData.AttachmentName, "application/pdf");
                mailMessage.Attachments.Add(attachment);
            }

            await client.SendMailAsync(mailMessage);
            _logger.LogInformation("Email sent successfully to {recipient}", emailData.ToEmail);
        }
        catch (SmtpException ex)
        {
            _logger.LogError(ex, "SMTP error while sending email to {recipient}: {error}", emailData.ToEmail, ex.Message);
            throw new ApplicationException("Failed to send email due to SMTP error", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error while sending email to {recipient}: {error}", emailData.ToEmail, ex.Message);
            throw new ApplicationException("Failed to send email due to unexpected error", ex);
        }
    }
}
