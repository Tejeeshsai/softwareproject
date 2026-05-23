"""
agent_sync.py - Cloud synchronization module for AURA-EDU Agent

Responsibilities:
- Send periodic heartbeat to cloud
- Fetch latest policy updates
- Upload violation logs (batched)
- Fail silently if offline

Design principles:
- Non-blocking (runs in separate thread)
- Offline-safe (enforcement continues if cloud unreachable)
- Retry logic for failed uploads
- No sensitive data in plaintext
"""

import requests
import time
import json
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from agent_logger import AgentLogger


class AgentSync:
    """Cloud synchronization with offline-first design"""
    
    def __init__(
        self,
        cloud_url: str = "https://api.aura-edu.com",
        timeout: int = 10
    ):
        """
        Initialize cloud sync module
        
        Args:
            cloud_url: Base URL of cloud API
            timeout: Request timeout in seconds
        """
        self.cloud_url = cloud_url.rstrip('/')
        self.timeout = timeout
        self.logger = AgentLogger()
        self.device_id = self.logger.get_device_id()
        
        # Track connection status
        self.last_successful_sync = None
        self.consecutive_failures = 0
        
        print(f"[SYNC] Initialized")
        print(f"[SYNC] Cloud URL: {self.cloud_url}")
        print(f"[SYNC] Device ID: {self.device_id[:16]}...")
    
    def heartbeat(self) -> bool:
        """
        Send periodic health check to cloud
        
        Returns:
            True if heartbeat successful, False otherwise
        """
        try:
            response = requests.post(
                f"{self.cloud_url}/agent/heartbeat",
                json={
                    "device_id": self.device_id,
                    "timestamp": time.time(),
                    "version": "1.0.0"
                },
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                self.last_successful_sync = time.time()
                self.consecutive_failures = 0
                return True
            else:
                print(f"[SYNC] Heartbeat failed: HTTP {response.status_code}")
                self.consecutive_failures += 1
                return False
                
        except requests.exceptions.RequestException as e:
            # Network error - fail silently (offline is OK)
            self.consecutive_failures += 1
            return False
        except Exception as e:
            print(f"[SYNC ERROR] Heartbeat exception: {e}")
            return False
    
    def fetch_policy(self) -> Optional[Dict]:
        """
        Download latest policy from cloud
        
        Returns:
            Policy dict if successful, None otherwise
        """
        try:
            response = requests.get(
                f"{self.cloud_url}/agent/policy",
                params={"device_id": self.device_id},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                policy_data = response.json()
                
                # Verify policy structure
                if self._validate_policy(policy_data):
                    self._save_policy(policy_data)
                    print(f"[SYNC] ✅ Policy updated")
                    return policy_data
                else:
                    print(f"[SYNC] ⚠️  Invalid policy received")
                    return None
            else:
                print(f"[SYNC] Policy fetch failed: HTTP {response.status_code}")
                return None
                
        except requests.exceptions.RequestException:
            # Offline - use cached policy
            return None
        except Exception as e:
            print(f"[SYNC ERROR] Policy fetch exception: {e}")
            return None
    
    def _validate_policy(self, policy: Dict) -> bool:
        """
        Validate policy structure before saving
        
        Args:
            policy: Policy dictionary
            
        Returns:
            True if valid, False otherwise
        """
        required_fields = ["mode", "usb_rules", "web_rules", "process_blocklist"]
        
        for field in required_fields:
            if field not in policy:
                print(f"[SYNC] Missing policy field: {field}")
                return False
        
        # Validate mode value
        if policy["mode"] not in ["LAB", "EXAM"]:
            print(f"[SYNC] Invalid mode: {policy['mode']}")
            return False
        
        return True
    
    def _save_policy(self, policy: Dict):
        """
        Save policy to local cache
        
        Args:
            policy: Policy dictionary
        """
        policy_file = Path("data/agent_policy.json")
        policy_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(policy_file, 'w') as f:
                json.dump(policy, f, indent=2)
            
            print(f"[SYNC] Policy saved to {policy_file}")
            
        except Exception as e:
            print(f"[SYNC ERROR] Failed to save policy: {e}")
    
    def upload_logs(self, batch_size: int = 50) -> bool:
        """
        Upload pending logs to cloud (batched)
        
        Args:
            batch_size: Number of logs to upload per batch
            
        Returns:
            True if upload successful, False otherwise
        """
        # Get unsynced logs
        logs = self.logger.get_unsynced_logs(limit=batch_size)
        
        if not logs:
            return True  # Nothing to upload
        
        try:
            # Format logs for upload
            formatted_logs = []
            for log in logs:
                log_id, timestamp, device_id, event_type, event_data = log
                formatted_logs.append({
                    "id": log_id,
                    "timestamp": timestamp,
                    "device_id": device_id,
                    "event_type": event_type,
                    "event_data": json.loads(event_data)
                })
            
            # Upload to cloud
            response = requests.post(
                f"{self.cloud_url}/agent/logs",
                json={
                    "device_id": self.device_id,
                    "logs": formatted_logs
                },
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                # Mark logs as synced
                log_ids = [log[0] for log in logs]
                self.logger.mark_synced(log_ids)
                
                print(f"[SYNC] ✅ Uploaded {len(logs)} logs")
                return True
            else:
                print(f"[SYNC] Log upload failed: HTTP {response.status_code}")
                return False
                
        except requests.exceptions.RequestException:
            # Network error - logs stay in queue
            return False
        except Exception as e:
            print(f"[SYNC ERROR] Log upload exception: {e}")
            return False
    
    def get_connection_status(self) -> Dict:
        """
        Get current connection status
        
        Returns:
            Status dictionary with connection info
        """
        if self.last_successful_sync is None:
            status = "never_connected"
            offline_duration = None
        elif self.consecutive_failures == 0:
            status = "online"
            offline_duration = 0
        else:
            status = "offline"
            offline_duration = time.time() - self.last_successful_sync
        
        return {
            "status": status,
            "last_sync": self.last_successful_sync,
            "offline_duration": offline_duration,
            "consecutive_failures": self.consecutive_failures
        }
    
    def sync_loop(self, interval: int = 60):
        """
        Main synchronization loop
        
        Args:
            interval: Sync interval in seconds (default: 60)
        """
        print(f"[SYNC] Starting sync loop (interval: {interval}s)")
        
        while True:
            try:
                # 1. Send heartbeat
                heartbeat_success = self.heartbeat()
                
                if heartbeat_success:
                    print(f"[SYNC] ✅ Heartbeat OK")
                else:
                    print(f"[SYNC] ⚠️  Heartbeat failed (failures: {self.consecutive_failures})")
                
                # 2. Fetch policy updates (every 5 minutes)
                if int(time.time()) % 300 == 0:
                    self.fetch_policy()
                
                # 3. Upload pending logs
                unsynced_count = len(self.logger.get_unsynced_logs(limit=1000))
                if unsynced_count > 0:
                    print(f"[SYNC] 📤 Uploading {unsynced_count} pending logs...")
                    
                    # Upload in batches
                    while unsynced_count > 0:
                        if self.upload_logs(batch_size=50):
                            unsynced_count = len(self.logger.get_unsynced_logs(limit=1000))
                        else:
                            print(f"[SYNC] Upload failed, {unsynced_count} logs remain in queue")
                            break
                
                # 4. Log sync status
                if int(time.time()) % 300 == 0:  # Every 5 minutes
                    status = self.get_connection_status()
                    self.logger.log_event("SYNC", {
                        "status": status["status"],
                        "consecutive_failures": status["consecutive_failures"]
                    })
                
                time.sleep(interval)
                
            except KeyboardInterrupt:
                print("\n[SYNC] Shutting down...")
                break
            except Exception as e:
                print(f"[SYNC ERROR] Sync loop error: {e}")
                time.sleep(interval)


def main():
    """Run sync module as standalone process"""
    
    # For testing, use a mock server URL
    sync = AgentSync(
        cloud_url="http://localhost:5000",  # Change to real API in production
        timeout=10
    )
    
    try:
        sync.sync_loop(interval=30)  # 30 seconds for testing
    except KeyboardInterrupt:
        print("\n[SYNC] Stopped by user")


if __name__ == "__main__":
    main()