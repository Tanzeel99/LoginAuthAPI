using LoginAuthAPI.Models;

namespace LoginAuthAPI.UtilityService
{
    public interface IEmailService
    {
        void SendEmail(EmailModel email);
    }
}
