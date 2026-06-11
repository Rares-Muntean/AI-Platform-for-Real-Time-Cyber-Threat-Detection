using Microsoft.AspNetCore.SignalR;
using System.Security.Claims;

namespace VeloSentry.API.Hubs
{
    public class CustomUserIdProvider : IUserIdProvider
    {
        public string? GetUserId(HubConnectionContext connection)
        {
            return connection.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? connection.User?.FindFirst("sub")?.Value;
        }
    }
}
