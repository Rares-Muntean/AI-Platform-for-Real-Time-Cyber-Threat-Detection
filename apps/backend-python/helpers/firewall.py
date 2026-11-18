import os
import platform
import socket
import subprocess
import threading
import time


class FirewallManager:
  CHAIN_NAME = "VELOX_BLOCK"
  NFQ_IN_CHAIN = "VELOX_NFQ_IN"
  NFQ_OUT_CHAIN = "VELOX_NFQ_OUT"

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

  def create_rule_list(self, name, out_in = "-i"):
      """Creates a new set of firewall rules, drops if exists already, adds rule to the newly created rule list"""
      self._run(["iptables", "-N", name], check=False)
      self._run(["iptables", "-F", name], check=True)
      self._run(
          ["iptables", "-A", name, out_in, "lo", "-j", "RETURN"],
          check=True,
      )

  def skip_protected_ports(self, rule_name):
      for proto_flag, port in [
          ("--dport", "22"),
          ("--sport", "5284"),
          ("--dport", "5005"),
      ]:
          self._run(
              [
                  "iptables",
                  "-A",
                  rule_name,
                  "-p",
                  "tcp",
                  proto_flag,
                  port,
                  "-j",
                  "RETURN",
              ],
              check=True,
          )

  def setup_chain(self):
    if not self.enabled or not self.is_linux_root:
      return

    self.create_rule_list(self.CHAIN_NAME)
    if self.protect_mgmt_ports:
        self.skip_protected_ports(self.CHAIN_NAME)

    check_jump = self._run(
        ["iptables", "-C", "INPUT", "-j", self.CHAIN_NAME], check=False
    )
    if check_jump.returncode != 0:
      self._run(["iptables", "-I", "INPUT", "1", "-j", self.CHAIN_NAME], check=True)

    print(
        f"[FIREWALL] Initialized iptables chain '{self.CHAIN_NAME}' (auto-unban:"
        f" {self.block_duration}s)."
    )

  def setup_nfqueue(self, queue_num=1, interface=None):
      if not self.is_linux_root:
          return

      # INPUT
      self.create_rule_list(self.NFQ_IN_CHAIN, "-i")

      for proto_flag, port in [("--sport", "5284"), ("--dport", "5005")]:
          self._run(
              [
                  "iptables",
                  "-A",
                  self.NFQ_IN_CHAIN,
                  "-p",
                  "tcp",
                  proto_flag,
                  port,
                  "-j",
                  "RETURN",
              ],
              check=True,
          )

      nfq_in_rule = ["iptables", "-A", self.NFQ_IN_CHAIN]
      if interface:
        nfq_in_rule += ["-i", interface]

      nfq_in_rule += [
          "-j",
          "NFQUEUE",
          "--queue-num",
          str(queue_num),
          "--queue-bypass"
      ]
      self._run(nfq_in_rule, check=True)

      # OUTPUT
      self.create_rule_list(self.NFQ_OUT_CHAIN, "-o")

      for proto_flag, port in [("--dport", "5284"), ("--sport", "5005")]:
          self._run(
              [
                  "iptables",
                  "-A",
                  self.NFQ_OUT_CHAIN,
                  "-p",
                  "tcp",
                  proto_flag,
                  port,
                  "-j",
                  "RETURN",
              ],
              check=True,
          )

      nfq_out_rule = ["iptables", "-A", self.NFQ_OUT_CHAIN]
      if interface:
          nfq_out_rule += ["-o", interface]

      nfq_out_rule += [
          "-j",
          "NFQUEUE",
          "--queue-num",
          str(queue_num),
          "--queue-bypass"
      ]
      self._run(nfq_out_rule, check=True)

      if self._run(["iptables", "-C", "INPUT", "-j", self.NFQ_IN_CHAIN], check=False).returncode != 0:
        pos = "2" if self.enabled else "1"
        self._run(["iptables", "-I", "INPUT", pos, "-j", self.NFQ_IN_CHAIN], check=True)

      if self._run(["iptables", "-C", "OUTPUT", "-j", self.NFQ_OUT_CHAIN], check=False).returncode != 0:
         self._run(
            ["iptables", "-I", "OUTPUT", "1", "-j", self.NFQ_OUT_CHAIN], check=True
         )

      print( f"[NFQUEUE] Inline firewall inspection active on Queue #{queue_num}"
      " (--queue-bypass enabled).")

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
      with self._lock:
          for timer in self.active_blocks.values():
              timer.cancel()
          self.active_blocks.clear()

      if self.is_linux_root:
          for parent, chain in [
              ("INPUT", self.NFQ_IN_CHAIN),
              ("OUTPUT", self.NFQ_OUT_CHAIN),
              ("INPUT", self.CHAIN_NAME),
          ]:
              self._run(["iptables", "-D", parent, "-j", chain], check=False)
              self._run(["iptables", "-F", chain], check=False)
              self._run(["iptables", "-X", chain], check=False)
          print("[FIREWALL] Cleaned up all VELOX iptables & NFQUEUE chains.")