namespace VeloSentry.API.Templates
{
    public class ServiceTemplates
    {
        public static string GetVeloxService(string remotePath)
        {
            return $@"
[Unit]
Description=Velox Security Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={remotePath}
ExecStart={remotePath}/velox-venv/bin/python3 -u {remotePath}/data_capture/sniffer.py
Restart=always

[Install]
WantedBy=multi-user.target";
        }
    }
}
