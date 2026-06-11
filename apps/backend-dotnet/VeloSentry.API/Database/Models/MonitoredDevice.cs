namespace VeloSentry.API.Database.Models
{
    public class MonitoredDevice
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string SshUsername { get; set; } = string.Empty;
        public string SshPassword { get; set; } = string.Empty;
        public string Status { get; set; } = "Offline";
        public DateTime LastHeartbeat { get; set; }

        public int UserId { get; set; }
        public User? User { get; set; }

        public ICollection<ThreatAlert> ThreatAlerts { get; set; } = new List<ThreatAlert>();
    }
}
