using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using VeloSentry.API.Database;
using VeloSentry.API.Database.Models;
using VeloSentry.API.Hubs;

namespace VeloSentry.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AlertsController : Controller
    {
        private readonly AppDbContext _db;
        private readonly IHubContext<VeloxHub> _hubContext;

        public AlertsController(AppDbContext db, IHubContext<VeloxHub> hubContext)
        {
            _db = db;
            _hubContext = hubContext;
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

            var device = await _db.MonitoredDevices.FirstOrDefaultAsync(d => d.IpAddress == alert.DestinationIp);
            if (device == null)
            {
                return NotFound(new { message = $"No monitored device registered with IP {alert.DestinationIp}" });
            }

            alert.UserId = device.UserId;
            alert.MonitoredDeviceId = device.Id;

            alert.UserId = device.UserId;
            _db.ThreatAlerts.Add(alert);
            await _db.SaveChangesAsync();

            await _hubContext.Clients.All.SendAsync("RecieveAlert", alert);

            return Ok(new { message = "Alert received successfully.", id = alert.Id });
        }
    }
}
