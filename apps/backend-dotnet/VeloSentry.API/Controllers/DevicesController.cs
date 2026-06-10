using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VeloSentry.API.Database;
using VeloSentry.API.Database.Models;
using VeloSentry.API.Services;

namespace VeloSentry.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DevicesController : Controller
    {
        private readonly AppDbContext _db;
        private readonly IDeviceProvisioningService _provisionService;

        public DevicesController(AppDbContext db, IDeviceProvisioningService provisionService)
        {
            _db = db;
            _provisionService = provisionService;
        }

        [HttpPost("register")]
        [Authorize]
        public async Task<IActionResult> RegisterDevice([FromBody] MonitoredDevice device)
        {
            device.Status = "Installing";
            device.LastHeartbeat = DateTime.UtcNow;

            _db.MonitoredDevices.Add(device);
            await _db.SaveChangesAsync();

            _ = Task.Run(async () =>
            {
                try
                {
                    await _provisionService.DeployAgentAsync(device);
                    device.Status = "Active";
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Deployment Failed: {ex.Message}");
                    device.Status = "Failed";
                }
                _db.Entry(device).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
                await _db.SaveChangesAsync();
            });

            return Ok(new { message = "Provisioning initiated.", deviceId = device.Id });
        }
    }
}
