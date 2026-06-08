using Microsoft.EntityFrameworkCore;
using VeloSentry.API.Database;
using VeloSentry.API.Database.Models;

namespace VeloSentry.API.Services
{
    public class UsersService : IUsersService
    {
        private readonly IPasswordService _passwordService;
        private readonly ITokenService _tokenService;
        private readonly AppDbContext _db;

        public UsersService(IPasswordService passwordService, ITokenService tokenService, AppDbContext db)
        {
            _passwordService = passwordService;
            _tokenService = tokenService;
            _db = db;
        }

        public async Task<string?> RegisterUser(User user)
        {
            user.Password = _passwordService.HashPassword(user.Password);

            _db.Users.Add(user);
            await _db.SaveChangesAsync();

            return _tokenService.CreateToken(user);
        }

        public async Task<string?> LoginUser(LoginDto loginDto)
        {
            User? user = await _db.Users.FirstOrDefaultAsync(x => x.Email == loginDto.Email);
            if (user == null) return null;

            bool verified = _passwordService.verifyPassword(loginDto.Password, user.Password);
            if (!verified) return null;

            return _tokenService.CreateToken(user);
        }
    }
}
