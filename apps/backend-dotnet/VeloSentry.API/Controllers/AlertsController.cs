using Microsoft.AspNetCore.Mvc;
using VeloSentry.API.Models;

namespace VeloSentry.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AlertsController : Controller
    {
        [HttpPost]
        public IActionResult RecieveAlert([FromBody] ThreatAlert alert)
        {
            // Store into Database / Push to frontend with websockets.

            Console.WriteLine($"[ALERT] Threat detected from IP: {alert.SourceIP}");
            Console.WriteLine($"Target IP: {alert.DestinationIP} |  Port: {alert.DestinationPort} | ANOMALY SCORE: {alert.AnomalyScore}");
            Console.WriteLine($"Protocol: {alert.Protocol}, Total Packets: {alert.TotalPackets}");
            Console.WriteLine($"Time Stamp: {alert.TimeStamp}");

            return Ok(new { message = "Alert received successfully." });
        }
    }
}
