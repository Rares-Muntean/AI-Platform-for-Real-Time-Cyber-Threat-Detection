using VeloSentry.API.Database.Models;

namespace VeloSentry.API.Services
{
    public interface ITokenService
    {
        string CreateToken(User user);
    }
}
