import os
import platform
import socket
import subprocess
import threading
import time


class FirewallManager:
  CHAIN_NAME = "VELOX_BLOCK"

  def __init__(
      self,
      enabled=True,
      block_duration=60,
      whitelist_ips=None,
      protect_mgmt_ports=True,
  ):
    self.enabled = enabled
    self.block_duration = block_duration
    self.protect_mgmt_ports = protect_mgmt_ports
    self.is_linux_root = platform.system() == "Linux" and os.geteuid() == 0

    self.whitelist = set(whitelist_ips or ["127.0.0.1"])
    self.whitelist.update(self._get_local_ips())

    self.active_blocks = {}
    self._lock = threading.Lock()

    if self.enabled and not self.is_linux_root:
      print(
          "[FIREWALL] Running in DRY-RUN mode (requires Linux + root for live"
          " iptables)."
      )

  def _get_local_ips(self):
    local_ips = {"127.0.0.1", "0.0.0.0"}

    try:
      hostname = socket.gethostname()
      for info in socket.getaddrinfo(hostname, None):
        local_ips.add(info[4][0])
    except Exception:
      pass

    if platform.system() == "Linux":
      try:
        out = subprocess.check_output(["hostname", "-I"], text=True).strip()
        for ip in out.split():
          local_ips.add(ip)
      except Exception:
        pass

    return local_ips

  def _run(self, cmd, check=True):
    return subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check
    )

  def setup_chain(self):
    if not self.enabled or not self.is_linux_root:
      return

    self._run(["iptables", "-N", self.CHAIN_NAME], check=False)
    self._run(["iptables", "-F", self.CHAIN_NAME], check=True)

    self._run(
        ["iptables", "-A", self.CHAIN_NAME, "-i", "lo", "-j", "RETURN"],
        check=True,
    )

    # Skip protected ports (FOR TESTING)
    if self.protect_mgmt_ports:
      self._run(
          [
              "iptables",
              "-A",
              self.CHAIN_NAME,
              "-p",
              "tcp",
              "--dport",
              "22",
              "-j",
              "RETURN",
          ],
          check=True,
      )
      self._run(
          [
              "iptables",
              "-A",
              self.CHAIN_NAME,
              "-p",
              "tcp",
              "--sport",
              "5284",
              "-j",
              "RETURN",
          ],
          check=True,
      )
      self._run(
          [
              "iptables",
              "-A",
              self.CHAIN_NAME,
              "-p",
              "tcp",
              "--dport",
              "5005",
              "-j",
              "RETURN",
          ],
          check=True,
      )

    check_jump = self._run(
        ["iptables", "-C", "INPUT", "-j", self.CHAIN_NAME], check=False
    )
    if check_jump.returncode != 0:
      self._run(["iptables", "-I", "INPUT", "1", "-j", self.CHAIN_NAME], check=True)

    print(
        f"[FIREWALL] Initialized iptables chain '{self.CHAIN_NAME}' (auto-unban:"
        f" {self.block_duration}s)."
    )

  def block_ip(self, ip):
    if not self.enabled:
      return False

    if ip in self.whitelist:
      print(f"[FIREWALL] Skipped whitelisted/local IP: {ip}")
      return False

    with self._lock:
      if ip in self.active_blocks:
        return False

      if self.is_linux_root:
        try:
          self._run(
              ["iptables", "-A", self.CHAIN_NAME, "-s", ip, "-j", "DROP"],
              check=True,
          )
        except subprocess.CalledProcessError as e:
          print(f"[FIREWALL ERROR] Failed to block {ip}: {e.stderr.strip()}")
          return False

      timer = threading.Timer(self.block_duration, self.unblock_ip, args=[ip])
      timer.daemon = True
      timer.start()
      self.active_blocks[ip] = timer

      mode_tag = "IPTABLES DROP" if self.is_linux_root else "DRY-RUN DROP"
      print(
          f"[FIREWALL] [{mode_tag}] Blocked {ip}"
          f" (duration: {self.block_duration}s)"
      )
      return True

  def unblock_ip(self, ip):
    with self._lock:
      timer = self.active_blocks.pop(ip, None)
      if timer:
        timer.cancel()

      if self.is_linux_root:
        self._run(
            ["iptables", "-D", self.CHAIN_NAME, "-s", ip, "-j", "DROP"],
            check=False,
        )
      print(f"[FIREWALL] Cooldown expired -> Unblocked {ip}")

  def cleanup(self):
    if not self.enabled:
      return
    with self._lock:
      for timer in self.active_blocks.values():
        timer.cancel()
      self.active_blocks.clear()

    if self.is_linux_root:
      self._run(["iptables", "-D", "INPUT", "-j", self.CHAIN_NAME], check=False)
      self._run(["iptables", "-F", self.CHAIN_NAME], check=False)
      self._run(["iptables", "-X", self.CHAIN_NAME], check=False)
      print(f"[FIREWALL] Cleaned up iptables chain '{self.CHAIN_NAME}'.")