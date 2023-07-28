namespace LoginAuthAPI.Models
{
    public class EmailModel
    {
        public string? To { get; set; }
        public string? Subject { get; set; }
        public string? Body { get; set; }

        public EmailModel(string to,string subject,string body) { 
            To = to;
            Subject = subject;
            Body = body;
        }
    }
}
