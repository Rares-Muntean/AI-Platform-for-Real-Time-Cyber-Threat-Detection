// BACKEND TYPES
export interface ThreatAlert {
    sourceIp: string;
    destinationIp: string;
    destinationPort: number;
    protocol: number;
    totalPackets: number;
    anomalyScore: number;
    timeStamp: string;
}

export interface User {
    firstName: string;
    lastName: string;
    email: string;
    password: string;
}

export interface UserDTO {
    firstName: string;
    lastName: string;
}

export interface LoginDTO {
    email: string;
    password: string;
}

export interface TokenResponse {
    token: string;
}

// DASHBOARD TYPES
export interface NavItem {
    name: string;
    icon: string;
    to: string;
}

export interface NavGroup {
    title: string;
    items: NavItem[];
}

export interface DisplayField {
    label: string;
    key: keyof ThreatAlert;
    format?: (val: any) => string;
}
