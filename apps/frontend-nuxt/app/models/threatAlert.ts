export interface ThreatAlert {
    sourceIp: string;
    destinationIp: string;
    destinationPort: number;
    protocol: number;
    totalPackets: number;
    anomalyScore: number;
    timeStamp: string;
}
