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

        [HttpGet("all")]
        public async Task<IActionResult> GetAlerts()
        {
            List<ThreatAlert> alerts = await _db.ThreatAlerts.OrderByDescending(a => a.TimeStamp).Take(100).ToListAsync();

            return Ok(alerts);
        }

        [HttpGet("last")]
        public async Task<IActionResult> GetLastAlert()
        {
            ThreatAlert? lastAlert = await _db.ThreatAlerts.OrderByDescending(a => a.TimeStamp).FirstOrDefaultAsync();
            if (lastAlert == null) return NotFound(new { message = "No alerts found in database." });

            return Ok(lastAlert);
        }

        [HttpPost("add")]
        public async Task<IActionResult> AddAlert([FromBody] ThreatAlert alert)
        {
            if (alert == null) return BadRequest();

            _db.ThreatAlerts.Add(alert);
            await _db.SaveChangesAsync();

            Console.WriteLine($"\n\nALERT saved with this IP: {alert.SourceIp}");
            Console.WriteLine($"Target IP: {alert.DestinationIp} |  Port: {alert.DestinationPort} | ANOMALY SCORE: {alert.AnomalyScore}");
            Console.WriteLine($"Protocol: {alert.Protocol}, Total Packets: {alert.TotalPackets}");
            Console.WriteLine($"Time Stamp: {alert.TimeStamp}");

            return Ok(new { message = "Alert received successfully.", id = alert.Id });
        }
    }
}
