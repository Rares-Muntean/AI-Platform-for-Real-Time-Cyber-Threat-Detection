using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using VeloSentry.API.Database;
using VeloSentry.API.Database.Models;
using VeloSentry.API.Hubs;
using VeloSentry.API.Services;

namespace VeloSentry.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DevicesController : Controller
    {
        private readonly AppDbContext _db;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly IHubContext<VeloxHub> _hubContext;

        public DevicesController(AppDbContext db, IServiceScopeFactory scopeFactory, IHubContext<VeloxHub> hubContext)
        {
            _db = db;
            _scopeFactory = scopeFactory;
            _hubContext = hubContext;
        }

        [HttpGet("all")]
        [Authorize]
        public async Task<IActionResult> GetDevices()
        {
            var devices = await _db.MonitoredDevices.OrderBy(d => d.Id).ToListAsync();
            return Ok(devices);
        }

        [HttpPost("register")]
        [Authorize]
        public async Task<IActionResult> RegisterDevice([FromBody] MonitoredDevice device)
        {
            var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                              ?? User.FindFirst("sub")?.Value;

            if (userIdClaim == null)
                return Unauthorized(new { message = "Invalid user token." });

            int userId = int.Parse(userIdClaim);

            device.UserId = userId;
            device.Status = "Installing";
            device.LastHeartbeat = DateTime.UtcNow;

            _db.MonitoredDevices.Add(device);
            await _db.SaveChangesAsync();

            _ = Task.Run(async () =>
            {
                using (var scope = _scopeFactory.CreateScope())
                {
                    var scopedDb = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                    var provisionService = scope.ServiceProvider.GetRequiredService<IDeviceProvisioningService>();

                    var dbDevice = await scopedDb.MonitoredDevices.FindAsync(device.Id);
                    if (dbDevice == null) return;

                    try
                    {
                        await provisionService.DeployAgentAsync(dbDevice);
                        dbDevice.Status = "Active";
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Deployment Failed: {ex.Message}");
                        dbDevice.Status = "Failed";
                    }

                    scopedDb.Entry(dbDevice).State = EntityState.Modified;
                    await scopedDb.SaveChangesAsync();

                    await _hubContext.Clients.All.SendAsync("DeviceStatusChanged", new { id = dbDevice.Id, status = dbDevice.Status });
                }

            });

            return Ok(device);
        }

        [HttpDelete("delete/{id}")]
        [Authorize]
        public async Task<IActionResult> DeleteDevice(int id)
        {
            MonitoredDevice? device = await _db.MonitoredDevices.FindAsync(id);
            if (device == null) return NotFound(new { message = "Device not found" });

            _db.MonitoredDevices.Remove(device);
            await _db.SaveChangesAsync();

            return Ok(new { message = "Device deleted succesfully" });
        }
    }
}
