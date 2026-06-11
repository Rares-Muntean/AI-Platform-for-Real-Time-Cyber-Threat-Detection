namespace VeloSentry.API.Database.Models
{
    public class ThreatAlert
    {
        public int Id { get; set; }
        public string SourceIp { get; set; } = string.Empty;
        public string DestinationIp { get; set; } = string.Empty;
        public int DestinationPort { get; set; }
        public int Protocol { get; set; }
        public double TotalPackets { get; set; }
        public double AnomalyScore { get; set; }
        public DateTime TimeStamp { get; set; }

        public int UserId { get; set; }
        public User? User { get; set; }

        public int MonitoredDeviceId { get; set; }
        public MonitoredDevice? MonitoredDevice { get; set; }
    }
}
