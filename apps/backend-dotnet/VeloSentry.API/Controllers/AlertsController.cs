using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VeloSentry.API.Database;
using VeloSentry.API.Database.Models;

namespace VeloSentry.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AlertsController : Controller
    {
        private readonly AppDbContext _db;
        public AlertsController(AppDbContext db)
        {
            _db = db;
        }

        [HttpGet]
        public async Task<IActionResult> GetAlerts()
        {
            List<ThreatAlert> alerts = await _db.ThreatAlerts.OrderByDescending(a => a.TimeStamp).Take(100).ToListAsync();

            return Ok(alerts);
        }

        [HttpPost]
        public async Task<IActionResult> RecieveAlert([FromBody] ThreatAlert alert)
        {
            if (alert == null) return BadRequest();

            _db.ThreatAlerts.Add(alert);
            await _db.SaveChangesAsync();

            Console.WriteLine($"\n\nALERT saved with this IP: {alert.SourceIP}");
            Console.WriteLine($"Target IP: {alert.DestinationIP} |  Port: {alert.DestinationPort} | ANOMALY SCORE: {alert.AnomalyScore}");
            Console.WriteLine($"Protocol: {alert.Protocol}, Total Packets: {alert.TotalPackets}");
            Console.WriteLine($"Time Stamp: {alert.TimeStamp}");

            return Ok(new { message = "Alert received successfully.", id = alert.Id });
        }
    }
}
