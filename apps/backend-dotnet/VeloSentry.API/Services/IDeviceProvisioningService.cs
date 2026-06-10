using VeloSentry.API.Database.Models;

namespace VeloSentry.API.Services
{
    public interface IDeviceProvisioningService
    {
        Task DeployAgentAsync(MonitoredDevice device);
    }
}