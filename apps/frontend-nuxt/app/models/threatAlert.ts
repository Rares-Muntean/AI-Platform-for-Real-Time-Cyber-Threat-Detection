export interface ThreatAlert {
    sourceIP: string;
    destinationIP: string;
    destinationPort: number;
    protocol: number;
    totalPackets: number;
    anomalyScore: number;
    timeStamp: string;
}
