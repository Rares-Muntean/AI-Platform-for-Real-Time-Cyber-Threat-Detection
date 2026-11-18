using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using NETCore.Encrypt;
using System.Text;
using System.Text.Json;
using VeloSentry.API.Database;
using VeloSentry.API.Database.Models;
using VeloSentry.API.Extensions;
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
        private readonly string _encryptionKey;
        private static readonly HttpClient _agentClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(5)
        };

        public DevicesController(AppDbContext db, IServiceScopeFactory scopeFactory, IHubContext<VeloxHub> hubContext, IConfiguration config)
        {
            _db = db;
            _scopeFactory = scopeFactory;
            _hubContext = hubContext;
            _encryptionKey = config["Security:EncryptionKey"] ?? "VeloxSentry_Encrypt_key_32_Char!";
        }

        [HttpGet("all")]
        [Authorize]
        public async Task<IActionResult> GetDevices()
        {
            try
            {
                int userId = User.GetUserId();
                var devices = await _db.MonitoredDevices.Where(d => d.UserId == userId).OrderBy(d => d.Id).ToListAsync();

                return Ok(devices);
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }
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
            device.SshPassword = EncryptProvider.AESEncrypt(device.SshPassword, _encryptionKey);

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
                        dbDevice.SshPassword = EncryptProvider.AESDecrypt(dbDevice.SshPassword, _encryptionKey);
                        await provisionService.DeployAgentAsync(dbDevice);
                        dbDevice.Status = "Active";
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Deployment Failed: {ex.Message}");
                        dbDevice.Status = "Failed";
                    }

                    dbDevice.SshPassword = EncryptProvider.AESEncrypt(dbDevice.SshPassword, _encryptionKey);
                    scopedDb.Entry(dbDevice).State = EntityState.Modified;
                    await scopedDb.SaveChangesAsync();

                    Console.WriteLine($"\n[SignalR] Broadcasting status change for Device {dbDevice.Id} to Active. Target User ID: {userId}");

                    await _hubContext.Clients.User(userId.ToString()).SendAsync("DeviceStatusChanged", new { id = dbDevice.Id, status = dbDevice.Status });
                }

            });

            return Ok(device);
        }

        [HttpGet("status/{id}")]
        [HttpPost("status/{id}")]
        [Authorize]
        public async Task<IActionResult> GetDeviceStatus(int id)
        {
            try
            {
                int userId = User.GetUserId();
                var device = await _db.MonitoredDevices.FirstOrDefaultAsync(d => d.Id == id && d.UserId == userId);
                if (device == null) return NotFound(new { message = "Device not found" });

                try
                {
                    var response = await _agentClient.GetAsync($"http://{device.IpAddress}:5005/status");
                    string json = await response.Content.ReadAsStringAsync();

                    if (!response.IsSuccessStatusCode)
                    {
                        return Ok(new { online = false, message = "Agent returned an error" });
                    }

                    using var doc = JsonDocument.Parse(json);
                    return Ok(new { online = true, data = doc.RootElement.Clone() });
                }
                catch
                {
                    return Ok(new { online = false, message = "Agent control API unreachable" });
                }
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }
        }

        [HttpPost("calibrate/{id}")]
        [Authorize]
        public async Task<IActionResult> CalibrateDevice(int id, [FromBody] CalibrateRequestDto request)
        {
            try
            {
                int userId = User.GetUserId();
                var device = await _db.MonitoredDevices.FirstOrDefaultAsync(d => d.Id == id && d.UserId == userId);
                if (device == null) return NotFound(new { message = "Device not found" });

                var payload = JsonSerializer.Serialize(new
                {
                    duration = request.Duration,
                    mode = string.IsNullOrWhiteSpace(request.Mode) ? "update" : request.Mode
                });

                var content = new StringContent(payload, Encoding.UTF8, "application/json");
                var response = await _agentClient.PostAsync($"http://{device.IpAddress}:5005/calibrate", content);
                string json = await response.Content.ReadAsStringAsync();

                return new ContentResult
                {
                    Content = json,
                    ContentType = "application/json",
                    StatusCode = (int)response.StatusCode
                };
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }
            catch (Exception ex)
            {
                return StatusCode(503, new { message = $"Could not reach agent: {ex.Message}" });
            }
        }

        [HttpPost("config/{id}")]
        [Authorize]
        public async Task<IActionResult> UpdateDeviceConfig(int id, [FromBody] AgentConfigDto request)
        {
            try
            {
                int userId = User.GetUserId();
                var device = await _db.MonitoredDevices.FirstOrDefaultAsync(d => d.Id == id && d.UserId == userId);
                if (device == null) return NotFound(new { message = "Device not found" });

                var configBody = new Dictionary<string, object?>
                {
                    ["interface"] = string.IsNullOrWhiteSpace(request.Interface) ? null : request.Interface.Trim(),
                    ["capture_mode"] = string.IsNullOrWhiteSpace(request.CaptureMode) ? "nfqueue" : request.CaptureMode.Trim(),
                    ["firewall_enabled"] = request.FirewallEnabled,
                    ["block_duration_seconds"] = request.BlockDurationSeconds,
                    ["device_ip_override"] = string.IsNullOrWhiteSpace(request.DeviceIpOverride) ? null : request.DeviceIpOverride.Trim()
                };

                var content = new StringContent(JsonSerializer.Serialize(configBody), Encoding.UTF8, "application/json");
                var response = await _agentClient.PostAsync($"http://{device.IpAddress}:5005/config", content);
                string json = await response.Content.ReadAsStringAsync();

                return new ContentResult
                {
                    Content = json,
                    ContentType = "application/json",
                    StatusCode = (int)response.StatusCode
                };
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }
            catch (Exception ex)
            {
                return StatusCode(503, new { message = $"Could not update agent config: {ex.Message}" });
            }
        }

        [HttpDelete("delete/{id}")]
        [Authorize]
        public async Task<IActionResult> DeleteDevice(int id)
        {
            try
            {
                int userId = User.GetUserId();
                MonitoredDevice? device = await _db.MonitoredDevices.FirstOrDefaultAsync(d => d.Id == id && d.UserId == userId);
                if (device == null) return NotFound(new { message = "Device not found" });

                _db.MonitoredDevices.Remove(device);
                await _db.SaveChangesAsync();
            }
            catch (UnauthorizedAccessException)
            {
                return Unauthorized();
            }


            return Ok(new { message = "Device deleted succesfully" });
        }
    }

    public class CalibrateRequestDto
    {
        public int Duration { get; set; } = 30;
        public string Mode { get; set; } = "update";
    }

    public class AgentConfigDto
    {
        public string? Interface { get; set; }
        public string CaptureMode { get; set; } = "nfqueue";
        public bool FirewallEnabled { get; set; } = true;
        public int BlockDurationSeconds { get; set; } = 60;
        public string? DeviceIpOverride { get; set; }
    }
}
