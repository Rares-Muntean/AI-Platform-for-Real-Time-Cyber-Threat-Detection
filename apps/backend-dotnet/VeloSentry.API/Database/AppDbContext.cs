using Microsoft.EntityFrameworkCore;
using VeloSentry.API.Database.Models;

namespace VeloSentry.API.Database
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        public DbSet<ThreatAlert> ThreatAlerts { get; set; }
    }
}
