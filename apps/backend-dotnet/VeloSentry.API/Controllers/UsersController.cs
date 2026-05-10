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

        public UsersController(IUsersService userService)
        {
            _userService = userService;
        }

        [HttpPost("create")]
        public async Task<IActionResult> CreateAccount([FromBody] User user)
        {
            await _userService.RegisterUser(user);
            return Ok(new { message = "Account created (pass tokens later)" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var token = await _userService.LoginUser(loginDto);
            if (token == null) return Unauthorized(new { message = "Invalid credentials" });

            return Ok(new { token });
        }
    }
}
