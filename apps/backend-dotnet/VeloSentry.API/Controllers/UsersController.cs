using Microsoft.AspNetCore.Mvc;
using VeloSentry.API.Database;
using VeloSentry.API.Database.Models;
using VeloSentry.API.Services;

namespace VeloSentry.API.Controllers
{
    public class UsersController : Controller
    {
        public readonly AppDbContext _db;
        public readonly IPasswordService _passwordService;

        public UsersController(AppDbContext db, IPasswordService passwordService)
        {
            _db = db;
            _passwordService = passwordService;
        }

        [HttpPost("create")]
        public async Task<IActionResult> CreateAccount([FromBody] User user)
        {
            user.Password = _passwordService.HashPassword(user.Password);

            _db.Users.Add(user);
            await _db.SaveChangesAsync();

            return Ok(new { message = "Account created (pass tokens later)" });
        }
    }
}
