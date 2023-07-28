namespace LoginAuthAPI.Models.DTO
{
    public record ResetPasswordDTO
    {
        public string? Email { get; set; }
        public string? EmailToken { get; set; }
        public string? NewPassword { get; set; }
        public string? ConfirmPassword { get; set; }
    }
}
