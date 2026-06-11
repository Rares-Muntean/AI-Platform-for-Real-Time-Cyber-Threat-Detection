using Renci.SshNet;
using System.Text;
using VeloSentry.API.Database.Models;
using VeloSentry.API.Templates;

namespace VeloSentry.API.Services
{
    public class DeviceProvisioningService : IDeviceProvisioningService
    {
        private readonly IConfiguration _config;

        public DeviceProvisioningService(IConfiguration config)
        {
            _config = config;
        }

        public async Task DeployAgentAsync(MonitoredDevice device)
        {
            await Task.Run(() =>
            {
                var connectionInfo = new Renci.SshNet.ConnectionInfo(device.IpAddress, device.SshUsername,
                    new PasswordAuthenticationMethod(device.SshUsername, device.SshPassword));

                using (var sftp = new SftpClient(connectionInfo))
                using (var ssh = new SshClient(connectionInfo))
                {
                    sftp.Connect();
                    ssh.Connect();

                    string remotePath = $"/home/{device.SshUsername}/backend-python";
                    RunLoggedCommand(ssh, $"mkdir -p {remotePath}");

                    Console.WriteLine("[SFTP] Starting directory upload...");
                    string localSourcePath = @"E:\A.Projects\PROJECTS-LICENTA\VELOX\apps\backend-python";
                    UploadDirectory(sftp, localSourcePath, remotePath);
                    Console.WriteLine("[SFTP] Directory upload complete.");

                    string targetIp = device.IpAddress;
                    string ipPrefix = string.Empty;
                    int lastDotIndex = targetIp.LastIndexOf('.');
                    if (lastDotIndex != -1)
                    {
                        ipPrefix = targetIp.Substring(0, lastDotIndex + 1);
                    }

                    string localIpAddress = "127.0.0.1";
                    var host = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());
                    bool matchFound = false;

                    foreach (var ip in host.AddressList)
                    {
                        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            string ipStr = ip.ToString();
                            if (ipStr != "127.0.0.1")
                            {
                                if (!string.IsNullOrEmpty(ipPrefix) && ipStr.StartsWith(ipPrefix))
                                {
                                    localIpAddress = ipStr;
                                    matchFound = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (!matchFound)
                    {
                        foreach (var ip in host.AddressList)
                        {
                            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && ip.ToString() != "127.0.0.1")
                            {
                                localIpAddress = ip.ToString();
                                break;
                            }
                        }
                    }

                    byte[] ipBytes = Encoding.UTF8.GetBytes(localIpAddress);

                    string remoteConfigPath = $"{remotePath}/helpers/ip_config.txt";
                    using (var configStream = new MemoryStream(ipBytes))
                    {
                        sftp.UploadFile(configStream, remoteConfigPath);
                    }
                    Console.WriteLine($"[SFTP] Dynamically configured agent with C# Host IP: {localIpAddress}");

                    var checkCmd = ssh.RunCommand("if dpkg -s python3-pip python3-venv libpcap-dev >/dev/null 2>&1; then echo 'INSTALLED'; else echo 'MISSING'; fi");
                    if (checkCmd.Result.Trim() == "INSTALLED")
                    {
                        Console.WriteLine("[SSH] System dependencies already satisfied. Skipping apt update/install.");
                    }
                    else
                    {
                        Console.WriteLine("[SSH] Dependencies missing. Installing via apt...");
                        string installCmd = $"echo '{device.SshPassword}' | sudo -S apt-get -o DPkg::Lock::TimeoutInterval=120 update && " +
                                            $"echo '{device.SshPassword}' | sudo -S apt-get -o DPkg::Lock::TimeoutInterval=120 install -y python3-pip python3-venv libpcap-dev";
                        RunLoggedCommand(ssh, installCmd);
                    }

                    string createVenvCmd = $"python3 -m venv --system-site-packages {remotePath}/velox-venv";
                    RunLoggedCommand(ssh, createVenvCmd);

                    string installReqsCmd = $"export PIP_NO_KEYRING=1 && " +
                        $"export PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring && " +
                        $"{remotePath}/velox-venv/bin/pip install --no-cache-dir -r {remotePath}/requirements.txt";
                    RunLoggedCommand(ssh, installReqsCmd);


                    string serviceFileContent = ServiceTemplates.GetVeloxService(remotePath);
                    byte[] byteArray = Encoding.UTF8.GetBytes(serviceFileContent);
                    string tempServicePath = $"/home/{device.SshUsername}/velox.service";

                    using (var memoryStream = new MemoryStream(byteArray))
                    {
                        sftp.UploadFile(memoryStream, tempServicePath);
                    }

                    string enableServiceCmd = $"echo '{device.SshPassword}' | sudo -S mv {tempServicePath} /etc/systemd/system/velox.service && " +
                                              $"echo '{device.SshPassword}' | sudo -S systemctl daemon-reload && " +
                                              $"echo '{device.SshPassword}' | sudo -S systemctl enable velox && " +
                                              $"echo '{device.SshPassword}' | sudo -S systemctl restart velox";
                    RunLoggedCommand(ssh, enableServiceCmd);

                    sftp.Disconnect();
                    ssh.Disconnect();
                    Console.WriteLine("=== DEPLOYMENT SUCCESSFUL ===");
                }
            });
        }

        private void RunLoggedCommand(SshClient ssh, string commandText)
        {
            Console.WriteLine($"\n[SSH EXEC] {commandText}");
            var cmd = ssh.CreateCommand(commandText);
            cmd.CommandTimeout = TimeSpan.FromMinutes(30);

            var asynch = cmd.BeginExecute();

            using (var reader = new StreamReader(cmd.OutputStream))
            {
                while (!asynch.IsCompleted || !reader.EndOfStream)
                {
                    string? line = reader.ReadLine();
                    if (!string.IsNullOrEmpty(line))
                    {
                        Console.WriteLine($"[SSH STDOUT] {line}");
                    }
                }
            }

            cmd.EndExecute(asynch);

            if (cmd.ExitStatus != 0)
            {
                using (var errorReader = new StreamReader(cmd.ExtendedOutputStream))
                {
                    string error = errorReader.ReadToEnd();
                    Console.WriteLine($"[SSH STDERR]\n{error}");
                    throw new Exception($"Command failed with exit code {cmd.ExitStatus}. Error: {error}");
                }
            }
        }

        private void UploadDirectory(SftpClient client, string localPath, string remotePath)
        {
            foreach (string file in Directory.GetFiles(localPath))
            {
                using (var stream = new FileStream(file, FileMode.Open))
                {
                    client.UploadFile(stream, remotePath + "/" + Path.GetFileName(file));
                }
            }

            foreach (string dir in Directory.GetDirectories(localPath))
            {
                if (dir.Contains(".venv") || dir.Contains("__pycache__") || dir.Contains("velox-env") || dir.Contains("velox-venv") || dir.Contains("datasets")) continue;

                string remoteSubDir = remotePath + "/" + Path.GetFileName(dir);
                if (!client.Exists(remoteSubDir))
                {
                    client.CreateDirectory(remoteSubDir);
                }
                UploadDirectory(client, dir, remoteSubDir);
            }
        }
    }
}