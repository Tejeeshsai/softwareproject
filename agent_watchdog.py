"""
agent_watchdog.py - Self-protection module for AURA-EDU Agent

Responsibilities:
- Monitor agent process (restart if killed)
- Detect binary tampering (hash verification)
- Lock configuration files (prevent editing)
- Log all tamper attempts

Design principles:
- Run as separate watchdog process
- Restart main agent if terminated
- Alert cloud on critical tampering
- Fail-secure (if watchdog dies, agent should still enforce)
"""

import os
import sys
import time
import psutil
import hashlib
import subprocess
from pathlib import Path
from typing import Optional
from agent_logger import AgentLogger


class AgentWatchdog:
    """Self-protection and tamper detection"""
    
    def __init__(
        self,
        agent_process_name: str = "python.exe",
        agent_script_path: str = "agent_main.py"
    ):
        """
        Initialize watchdog
        
        Args:
            agent_process_name: Name of agent process to monitor
            agent_script_path: Path to main agent script
        """
        self.agent_process_name = agent_process_name
        self.agent_script_path = Path(agent_script_path)
        self.logger = AgentLogger()
        
        # Calculate hash of agent binary
        self.agent_binary_path = self._get_agent_binary_path()
        self.original_hash = self._calculate_file_hash(self.agent_binary_path)
        
        # Configuration files to protect
        self.protected_files = [
            "agent_policy.json",
            "agent_mode.json",
            "data/device_id.txt"
        ]
        
        print(f"[WATCHDOG] Initialized")
        print(f"[WATCHDOG] Monitoring: {self.agent_process_name}")
        print(f"[WATCHDOG] Binary hash: {self.original_hash[:16]}...")
    
    def _get_agent_binary_path(self) -> Path:
        """
        Get path to agent executable/script
        
        Returns:
            Path to agent binary
        """
        # For now, monitor the Python executable
        # In production, this would be the compiled .exe
        return Path(sys.executable)
    
    def _calculate_file_hash(self, filepath: Path) -> str:
        """
        Calculate SHA256 hash of file
        
        Args:
            filepath: Path to file
            
        Returns:
            Hexadecimal hash string
        """
        if not filepath.exists():
            return ""
        
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            print(f"[WATCHDOG ERROR] Failed to hash {filepath}: {e}")
            return ""
    
    def check_agent_running(self) -> bool:
        """
        Check if agent process is running
        
        Returns:
            True if agent is running, False otherwise
        """
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                # Check if this is our agent process
                if proc.info['name'] == self.agent_process_name:
                    cmdline = proc.info.get('cmdline', [])
                    if cmdline and str(self.agent_script_path) in ' '.join(cmdline):
                        return True
            return False
        except Exception as e:
            print(f"[WATCHDOG ERROR] Failed to check process: {e}")
            return False
    
    def restart_agent(self):
        """
        Restart agent process if killed
        """
        print("[WATCHDOG] ⚠️  Agent not running! Attempting restart...")
        
        # Log tamper attempt
        self.logger.log_event("TAMPER", {
            "action": "agent_killed",
            "response": "restarting",
            "timestamp": time.time()
        })
        
        try:
            # Restart agent as subprocess
            subprocess.Popen(
                [sys.executable, str(self.agent_script_path)],
                creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
            )
            print("[WATCHDOG] ✅ Agent restarted")
            
        except Exception as e:
            print(f"[WATCHDOG ERROR] Failed to restart agent: {e}")
            self.logger.log_event("TAMPER", {
                "action": "restart_failed",
                "error": str(e)
            })
    
    def check_binary_integrity(self) -> bool:
        """
        Verify agent binary hasn't been modified
        
        Returns:
            True if binary is intact, False if tampered
        """
        current_hash = self._calculate_file_hash(self.agent_binary_path)
        
        if current_hash != self.original_hash:
            print("[WATCHDOG] 🚨 CRITICAL: Binary modified!")
            
            self.logger.log_event("TAMPER", {
                "action": "binary_modified",
                "original_hash": self.original_hash,
                "current_hash": current_hash,
                "critical": True
            })
            
            return False
        
        return True
    
    def lock_config_files(self):
        """
        Set config files as read-only and hidden (Windows)
        """
        for config_file in self.protected_files:
            filepath = Path(config_file)
            
            if not filepath.exists():
                continue
            
            try:
                if os.name == 'nt':  # Windows
                    # Set read-only + system file attributes
                    os.system(f'attrib +R +S +H "{filepath}" >nul 2>&1')
                else:  # Linux/Mac
                    os.chmod(filepath, 0o444)  # Read-only
                
            except Exception as e:
                print(f"[WATCHDOG ERROR] Failed to lock {filepath}: {e}")
    
    def unlock_config_files(self):
        """
        Temporarily unlock config files (for legitimate updates)
        """
        for config_file in self.protected_files:
            filepath = Path(config_file)
            
            if not filepath.exists():
                continue
            
            try:
                if os.name == 'nt':  # Windows
                    os.system(f'attrib -R -S -H "{filepath}" >nul 2>&1')
                else:  # Linux/Mac
                    os.chmod(filepath, 0o644)  # Read/write
                
            except Exception as e:
                print(f"[WATCHDOG ERROR] Failed to unlock {filepath}: {e}")
    
    def detect_debugger(self) -> bool:
        """
        Detect if agent is being debugged (anti-reverse-engineering)
        
        Returns:
            True if debugger detected
        """
        # Basic debugger detection (Windows)
        if os.name == 'nt':
            try:
                import ctypes
                return ctypes.windll.kernel32.IsDebuggerPresent() != 0
            except Exception:
                return False
        return False
    
    def monitor_loop(self, interval: int = 5):
        """
        Main watchdog monitoring loop
        
        Args:
            interval: Check interval in seconds
        """
        print(f"[WATCHDOG] Starting monitor loop (interval: {interval}s)")
        
        consecutive_failures = 0
        
        while True:
            try:
                # 1. Check if agent is running
                if not self.check_agent_running():
                    consecutive_failures += 1
                    print(f"[WATCHDOG] Agent not running ({consecutive_failures}/3)")
                    
                    if consecutive_failures >= 3:
                        self.restart_agent()
                        consecutive_failures = 0
                else:
                    consecutive_failures = 0
                
                # 2. Check binary integrity (every 30 seconds)
                if int(time.time()) % 30 == 0:
                    if not self.check_binary_integrity():
                        # Critical tamper - alert immediately
                        print("[WATCHDOG] 🚨 Binary compromised!")
                
                # 3. Lock configuration files
                self.lock_config_files()
                
                # 4. Detect debugger
                if self.detect_debugger():
                    print("[WATCHDOG] ⚠️  Debugger detected!")
                    self.logger.log_event("TAMPER", {
                        "action": "debugger_detected",
                        "timestamp": time.time()
                    })
                
                # 5. Health check log (every 5 minutes)
                if int(time.time()) % 300 == 0:
                    self.logger.log_event("HEALTH", {
                        "component": "watchdog",
                        "status": "running"
                    })
                
                time.sleep(interval)
                
            except KeyboardInterrupt:
                print("\n[WATCHDOG] Shutting down...")
                break
            except Exception as e:
                print(f"[WATCHDOG ERROR] Monitor loop error: {e}")
                time.sleep(interval)


def main():
    """Run watchdog as standalone process"""
    watchdog = AgentWatchdog(
        agent_process_name="python.exe",
        agent_script_path="agent_main.py"
    )
    
    try:
        watchdog.monitor_loop(interval=5)
    except KeyboardInterrupt:
        print("\n[WATCHDOG] Stopped by user")


if __name__ == "__main__":
    main()