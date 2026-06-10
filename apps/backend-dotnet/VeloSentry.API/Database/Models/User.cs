namespace VeloSentry.API.Database.Models
{
    public class User
    {
        public int Id { get; set; }
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;

        public ICollection<ThreatAlert> ThreatAlerts { get; set; } = new List<ThreatAlert>();
        public ICollection<MonitoredDevice> MonitoredDevices { get; set; } = new List<MonitoredDevice>();

    }
}
