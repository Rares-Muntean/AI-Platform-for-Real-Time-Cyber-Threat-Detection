namespace VeloSentry.API.Services
{
    public interface IPasswordService
    {
        string HashPassword(string password);
        bool verifyPassword(string password, string hashedPassword);
    }
}
