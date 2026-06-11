using System.Security.Claims;

namespace VeloSentry.API.Extensions
{
    public static class ClaimsPrincipalExtensions
    {
        public static int GetUserId(this ClaimsPrincipal user)
        {
            var userIdClaim = user.FindFirst(ClaimTypes.NameIdentifier)?.Value
                             ?? user.FindFirst("sub")?.Value;

            if (userIdClaim == null)
                throw new UnauthorizedAccessException("User ID claim is missing from token.");

            return int.Parse(userIdClaim);
        }
    }
}
