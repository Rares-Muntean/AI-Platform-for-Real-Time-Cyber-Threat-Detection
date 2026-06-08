using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VeloSentry.API.Database.Models;
using VeloSentry.API.Services;

namespace VeloSentry.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : Controller
    {
        public readonly IUsersService _userService;
        public readonly IConfiguration _config;

        public UsersController(IUsersService userService, IConfiguration config)
        {
            _userService = userService;
            _config = config;
        }

        [HttpPost("create")]
        public async Task<IActionResult> CreateAccount([FromBody] User user)
        {
            string? token = await _userService.RegisterUser(user);
            if (token == null) return Unauthorized(new { message = "Register Unsuccesful" });

            SetJwtCookie(token);
            return Ok(new { message = "User registered successfully" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            string? token = await _userService.LoginUser(loginDto);
            if (token == null) return Unauthorized(new { message = "Invalid credentials" });

            SetJwtCookie(token);
            return Ok(new { message = "Login successful" });
        }

        [Authorize]
        [HttpPost("logout")]
        public IActionResult LogoutAdmin()
        {
            Response.Cookies.Delete("jwt");

            return Ok(new { success = true });
        }

        [Authorize]
        [HttpGet("verifyToken")]
        public IActionResult VerifyToken()
        {
            string? firstName = User.FindFirst("FirstName")?.Value;
            string? lastName = User.FindFirst("LastName")?.Value;

            return Ok(new { valid = true, user = new UserDto { FirstName = firstName, LastName = lastName } });
        }

        private void SetJwtCookie(string token)
        {
            Response.Cookies.Append("jwt", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = false,
                SameSite = SameSiteMode.Lax,
                Expires = DateTime.UtcNow.AddMinutes(_config.GetValue<int>("JWT:ExpireMinutes"))
            });
        }
    }
}
