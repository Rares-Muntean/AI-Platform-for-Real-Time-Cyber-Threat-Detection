using VeloSentry.API.Database.Models;

namespace VeloSentry.API.Services
{
    public interface IUsersService
    {
        Task RegisterUser(User user);
        Task<string?> LoginUser(LoginDto loginDto);
    }
}