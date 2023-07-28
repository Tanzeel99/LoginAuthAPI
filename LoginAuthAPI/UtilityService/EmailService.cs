using LoginAuthAPI.Models;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace LoginAuthAPI.UtilityService
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public void SendEmail(EmailModel email)
        {
            var emailmessage = new MimeMessage();
            var from = _configuration["EmailSettings:From"];
            emailmessage.From.Add(new MailboxAddress("Tanzeel", from));
            emailmessage.To.Add(new MailboxAddress(email.To, email.To));
            emailmessage.Subject = email.Subject;
            emailmessage.Body = new TextPart(MimeKit.Text.TextFormat.Html)
            {
                Text = string.Format(email.Body)
            };
            using (var client = new SmtpClient())
            {
                try
                {
                    client.Connect("smtp.gmail.com", 465, true);
                    client.Authenticate(_configuration["EmailSettings:Username"], _configuration["EmailSettings:Password"]);
                    client.Send(emailmessage);
                }
                catch (Exception error)
                {

                    throw;
                }
                finally 
                { 
                    client.Disconnect(true); 
                    client.Dispose(); 
                }
            }
        }
    }
}
