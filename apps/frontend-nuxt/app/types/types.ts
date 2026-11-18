// BACKEND TYPES
export interface ThreatAlert {
    id: number;
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

export interface MonitoredDevice {
    id: number;
    name: string;
    ipAddress: string;
    sshUsername: string;
    sshPassword: string;
    status: string;
    lastHeartbeat: Date;
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

export interface CalibrationState {
    status: "idle" | "recording" | "training";
    mode: "update" | "replace";
    recordedFlows: number;
    secondsRemaining: number;
    lastResult: "success" | "error" | null;
    lastMessage: string | null;
    lastCalibratedAt: string | null;
}

export interface AgentStatusData {
    agent: string;
    captureMode: string;
    interface: string | null;
    firewallEnabled: boolean;
    blockDurationSeconds: number;
    deviceIpOverride: string | null;
    threshold: number;
    activeBlocks: string[];
    calibration: CalibrationState;
}

export interface AgentStatusResponse {
    online: boolean;
    message?: string;
    data?: AgentStatusData;
}

export interface CalibratePayload {
    duration: number;
    mode: "update" | "replace";
}

export interface AgentConfigPayload {
    interface: string | null;
    captureMode: string;
    firewallEnabled: boolean;
    blockDurationSeconds: number;
    deviceIpOverride: string | null;
}
