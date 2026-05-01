namespace VeloSentry.API.Models
{
    public class ThreatAlert
    {
        public string SourceIP { get; set; } = string.Empty;
        public string DestinationIP { get; set; } = string.Empty;
        public int DestinationPort { get; set; }
        public int Protocol { get; set; }
        public double TotalPackets { get; set; }
        public double AnomalyScore { get; set; }
        public DateTime TimeStamp { get; set; }
    }
}
