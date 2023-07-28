using LoginAuthAPI.Context;
using LoginAuthAPI.Helpers;
using LoginAuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using System.Security.Cryptography;
using LoginAuthAPI.Models.DTO;
using LoginAuthAPI.UtilityService;

namespace LoginAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly dbContext _dbContext;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        public UserController(dbContext dbContext, IConfiguration configuration, IEmailService emailService)
        {
            _dbContext = dbContext;
            _configuration = configuration;
            _emailService = emailService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Authenticate([FromBody] User data)
        {
            if (data == null)
                return BadRequest();

            var user = await _dbContext.Users.FirstOrDefaultAsync(a => a.Username == data.Username);
            if (user == null)
                return NotFound(new { Message = "User Not Found" });

            if (!PasswordHasher.VerifyPassword(data.Password, user.Password))
            {
                return BadRequest(new { Message = "Wrong Password" });
            }

            user.Token = CreateJwt(user);
            user.RefreshToken = CreateRefreshToken();
            user.RefreshTokenExpiry = DateTime.Now.AddDays(5);
            await _dbContext.SaveChangesAsync();
            return Ok(new TokenApiDTO
            {
                AccessToken = user.Token,
                RefreshToken = user.RefreshToken
            });
        }

        [HttpPost("signup")]
        public async Task<IActionResult> signUp([FromBody] User data)
        {
            if (data == null)
                return BadRequest();

            if (await checkUserExist(data.Username))
                return BadRequest(new { Message = "User already used." });

            if (await checkEmailExist(data.Email))
                return BadRequest(new { Message = "Email already exists." });

            var passMessage = CheckPasswordStrength(data.Password);
            if (!string.IsNullOrEmpty(passMessage))
                return BadRequest(new { Message = passMessage.ToString() });

            data.Password = PasswordHasher.HashPassword(data.Password);
            data.Role = "User";
            data.Token = "";
            await _dbContext.Users.AddAsync(data);
            await _dbContext.SaveChangesAsync();

            return Ok(new { Message = "User Created" });
        }

        private Task<bool> checkUserExist(string username)
        {
            return _dbContext.Users.AnyAsync(a => a.Username == username);
        }

        private Task<bool> checkEmailExist(string email)
        {
            return _dbContext.Users.AnyAsync(a => a.Email == email);
        }

        private static string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if (password.Length < 9)
                sb.Append("Minimum password length should be 8" + Environment.NewLine);
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password should be AlphaNumeric" + Environment.NewLine);
            if (!Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,-,=]"))
                sb.Append("Password should contain special charcter" + Environment.NewLine);
            return sb.ToString();
        }

        private string CreateJwt(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("Tanzeel@12345678");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name,$"{user.Username}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(5),
                /*Expires = DateTime.Now.AddDays(1),*/
                SigningCredentials = credentials
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }

        [Authorize]
        [HttpGet("getUsers")]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _dbContext.Users.ToListAsync());
        }

        private string CreateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshtoken = Convert.ToBase64String(tokenBytes);
            var Rtokenpresent = _dbContext.Users.Any(a => a.RefreshToken == refreshtoken);
            if (Rtokenpresent)
            {
                return CreateRefreshToken();
            }
            return refreshtoken;
        }

        private ClaimsPrincipal GetPrincipleFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("Tanzeel@12345678")),
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("This is Invalid Token");
            return principal;
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] TokenApiDTO tokenApiDto)
        {
            if (tokenApiDto is null)
                return BadRequest("Invalid Client Request");
            string accessToken = tokenApiDto.AccessToken;
            string refreshToken = tokenApiDto.RefreshToken;
            var principal = GetPrincipleFromExpiredToken(accessToken);
            var username = principal.Identity.Name;
            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiry <= DateTime.Now)
                return BadRequest("Invalid Request");
            var newAccessToken = CreateJwt(user);
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _dbContext.SaveChangesAsync();
            return Ok(new TokenApiDTO()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
            });
        }

        [HttpPost("send-reset-email/{email}")]
        public async Task<IActionResult> SendEmail(string email)
        {
            var user = await _dbContext.Users.FirstOrDefaultAsync(a=>a.Email == email);
            if(user is null)
            {
                return NotFound(new
                {
                    StatusCode = 404,
                    Message = "Email doesn't exist"
                });
            }
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var emailToken = Convert.ToBase64String(tokenBytes);
            user.ResetPasswordToken = emailToken;
            user.ResetPasswordTokenExpiry = DateTime.Now.AddMinutes(15);
            string from = _configuration["EmailSettings:From"];
            var emailModel = new EmailModel(email, "Reset Password",EmailContent.Email(email,emailToken));
            _emailService.SendEmail(emailModel);
            _dbContext.Entry(user).State = EntityState.Modified;
            await _dbContext.SaveChangesAsync();
            return Ok(new
            {
                StatusCode = 200,
                Message = "Email Sent"
            });
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDTO resetPassword)
        {
            var newToken = resetPassword.EmailToken.Replace(" ", "+");
            var user = await _dbContext.Users.AsNoTracking().FirstOrDefaultAsync(a=>a.Email == resetPassword.Email);
            if (user is null)
            {
                return NotFound(new
                {
                    StatusCode = 404,
                    Message = "User doesn't exist"
                });
            }
            var tokenCode = user.ResetPasswordToken;
            DateTime emailTokenExpiry = user.ResetPasswordTokenExpiry;
            if(tokenCode != resetPassword.EmailToken || emailTokenExpiry < DateTime.Now) 
            {
                return BadRequest(new
                {
                    StatusCode = 400,
                    Message = "Invalid reset link"
                }) ;
            }
            user.Password = PasswordHasher.HashPassword(resetPassword.NewPassword);
            _dbContext.Entry(user).State = EntityState.Modified;
            await _dbContext.SaveChangesAsync();
            return Ok(new { 
                StatusCode = 200,
                Message = "Password reset successfully"
            });
        }
    }
}
