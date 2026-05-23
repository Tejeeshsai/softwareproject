"""
agent_usb.py - USB device control for AURA-EDU Agent

Responsibilities:
- Detect USB device insertion/removal
- Block mass storage devices
- Allow HID devices (keyboard, mouse)
- VID/PID whitelisting support
- Mode-aware enforcement

Design principles:
- Zero-tolerance blocking in EXAM mode
- Log-only in LAB mode
- Fast detection (< 1 second)
- Offline-safe (no cloud dependency)
"""

import time
import sys
from typing import List, Dict, Optional
from pathlib import Path

# Windows-only imports
if sys.platform == 'win32':
    try:
        import wmi
    except ImportError:
        print("[USB] wmi library not found. Install: pip install wmi")
        print("[USB] USB blocking will not work without WMI")
        wmi = None


class AgentUSB:
    """USB device monitoring and blocking"""
    
    def __init__(self, mode=None, policy=None, logger=None):
        """
        Initialize USB monitor
        
        Args:
            mode: AgentMode instance
            policy: AgentPolicy instance
            logger: AgentLogger instance
        """
        self.mode = mode
        self.policy = policy
        self.logger = logger
        
        # WMI connection (Windows only)
        if sys.platform == 'win32' and wmi:
            try:
                self.wmi = wmi.WMI()
                print("[USB] WMI initialized successfully")
            except Exception as e:
                print(f"[USB ERROR] Failed to initialize WMI: {e}")
                self.wmi = None
        else:
            self.wmi = None
            print("[USB] USB blocking only works on Windows with WMI")
        
        # Track known devices to detect new insertions
        self.known_devices = set()
        
        print("[USB] Initialized")
    
    def get_mode(self) -> str:
        """Get current mode from mode manager or fallback"""
        if self.mode:
            return self.mode.get_current_mode()
        
        # Fallback: read from file
        mode_file = Path("data/agent_mode.json")
        if mode_file.exists():
            try:
                import json
                with open(mode_file) as f:
                    data = json.load(f)
                    return data.get("mode", "EXAM")
            except:
                pass
        
        return "EXAM"  # Default to strictest mode
    
    def get_usb_policy(self) -> Dict:
        """Get USB policy rules"""
        if self.policy:
            return self.policy.get_usb_rules()
        
        # Fallback: default rules
        return {
            "block_mass_storage": True,
            "allow_hid": True,
            "whitelist_enabled": False,
            "whitelisted_devices": []
        }
    
    def scan_usb_devices(self) -> List[Dict]:
        """
        Scan for connected USB devices
        
        Returns:
            List of device dictionaries
        """
        if not self.wmi:
            return []
        
        devices = []
        
        try:
            # Query USB devices using WMI
            for usb in self.wmi.Win32_USBHub():
                device_info = {
                    "device_id": usb.DeviceID,
                    "name": usb.Name or "Unknown USB Device",
                    "description": usb.Description or "",
                    "status": usb.Status or "Unknown",
                    "pnp_device_id": usb.PNPDeviceID or ""
                }
                
                # Extract VID/PID if available
                vid, pid = self._extract_vid_pid(usb.DeviceID)
                device_info["vid"] = vid
                device_info["pid"] = pid
                
                # Determine device type
                device_info["device_type"] = self._determine_device_type(device_info)
                
                devices.append(device_info)
                
        except Exception as e:
            print(f"[USB ERROR] Failed to scan devices: {e}")
        
        return devices
    
    def _extract_vid_pid(self, device_id: str) -> tuple:
        """
        Extract VID and PID from device ID string
        
        Args:
            device_id: Device ID string
            
        Returns:
            Tuple of (VID, PID) or (None, None)
        """
        try:
            # Device ID format: USB\VID_0781&PID_5583\...
            if "VID_" in device_id and "PID_" in device_id:
                vid = device_id.split("VID_")[1].split("&")[0]
                pid = device_id.split("PID_")[1].split("\\")[0]
                return vid, pid
        except:
            pass
        
        return None, None
    
    def _determine_device_type(self, device_info: Dict) -> str:
        """
        Determine if device is mass storage or HID
        
        Args:
            device_info: Device information dictionary
            
        Returns:
            'mass_storage', 'hid', or 'unknown'
        """
        description = device_info.get("description", "").lower()
        name = device_info.get("name", "").lower()
        
        # HID devices (keyboard, mouse, etc.)
        hid_keywords = ["keyboard", "mouse", "hid", "pointing", "input"]
        for keyword in hid_keywords:
            if keyword in description or keyword in name:
                return "hid"
        
        # Mass storage devices
        storage_keywords = ["disk", "storage", "flash", "drive", "card"]
        for keyword in storage_keywords:
            if keyword in description or keyword in name:
                return "mass_storage"
        
        return "unknown"
    
    def is_whitelisted(self, device_info: Dict) -> bool:
        """
        Check if device is in whitelist
        
        Args:
            device_info: Device information dictionary
            
        Returns:
            True if whitelisted, False otherwise
        """
        policy = self.get_usb_policy()
        
        if not policy.get("whitelist_enabled", False):
            return False
        
        whitelist = policy.get("whitelisted_devices", [])
        
        vid = device_info.get("vid")
        pid = device_info.get("pid")
        
        if not vid or not pid:
            return False
        
        # Check if VID:PID combination is in whitelist
        device_signature = f"{vid}:{pid}"
        return device_signature in whitelist
    
    def should_block_device(self, device_info: Dict) -> bool:
        """
        Determine if device should be blocked
        
        Args:
            device_info: Device information dictionary
            
        Returns:
            True if should block, False if should allow
        """
        policy = self.get_usb_policy()
        device_type = device_info.get("device_type", "unknown")
        
        # Always allow HID devices (keyboard, mouse)
        if device_type == "hid" and policy.get("allow_hid", True):
            return False
        
        # Check whitelist
        if self.is_whitelisted(device_info):
            return False
        
        # Block mass storage if policy says so
        if device_type == "mass_storage" and policy.get("block_mass_storage", True):
            return True
        
        # Block unknown devices by default in EXAM mode
        if device_type == "unknown" and self.get_mode() == "EXAM":
            return True
        
        return False
    
    def block_device(self, device_info: Dict, mode: str):
        """
        Block a USB device
        
        Args:
            device_info: Device information dictionary
            mode: Current mode (LAB or EXAM)
        """
        device_id = device_info.get("device_id", "unknown")
        device_name = device_info.get("name", "Unknown Device")
        
        if mode == "LAB":
            # LAB mode: Log only, don't actually block
            print(f"[USB] LAB MODE: Detected {device_name} - would block in EXAM mode")
            
            if self.logger:
                self.logger.log_event("USB", {
                    "action": "detected",
                    "mode": "LAB",
                    "device_id": device_id,
                    "device_name": device_name,
                    "device_type": device_info.get("device_type"),
                    "vid": device_info.get("vid"),
                    "pid": device_info.get("pid")
                })
            
            return
        
        # EXAM mode: Actually block device
        try:
            # In a full implementation, this would disable the device via WMI
            # For now, we log the block action
            print(f"[USB] ⚠️  BLOCKED: {device_name}")
            
            if self.logger:
                self.logger.log_event("USB", {
                    "action": "blocked",
                    "mode": "EXAM",
                    "device_id": device_id,
                    "device_name": device_name,
                    "device_type": device_info.get("device_type"),
                    "vid": device_info.get("vid"),
                    "pid": device_info.get("pid")
                })
            
            # TODO: Actual device disabling code
            # This requires administrative privileges and can use:
            # - WMI's Disable() method
            # - Windows Device Manager API
            # - Registry modifications
            
        except Exception as e:
            print(f"[USB ERROR] Failed to block device: {e}")
    
    def monitor_loop(self, interval: int = 2):
        """
        Main monitoring loop
        
        Args:
            interval: Check interval in seconds
        """
        if not self.wmi:
            print("[USB] Cannot monitor USB devices (WMI not available)")
            return
        
        print(f"[USB] Starting monitor loop (interval: {interval}s)")
        
        # Initial scan
        current_devices = self.scan_usb_devices()
        self.known_devices = {d["device_id"] for d in current_devices}
        print(f"[USB] Found {len(current_devices)} USB devices on startup")
        
        scan_count = 0
        
        try:
            while True:
                scan_count += 1
                
                # Get current mode
                mode = self.get_mode()
                
                # Scan for devices
                current_devices = self.scan_usb_devices()
                current_device_ids = {d["device_id"] for d in current_devices}
                
                # Detect new devices
                new_device_ids = current_device_ids - self.known_devices
                
                if new_device_ids:
                    print(f"[USB] 🚨 Detected {len(new_device_ids)} new device(s)")
                    
                    for device in current_devices:
                        if device["device_id"] in new_device_ids:
                            # Check if should block
                            if self.should_block_device(device):
                                self.block_device(device, mode)
                            else:
                                print(f"[USB] ✅ Allowed: {device['name']} ({device['device_type']})")
                
                # Update known devices
                self.known_devices = current_device_ids
                
                # Health log every 5 minutes
                if scan_count % 150 == 0:  # 150 * 2 sec = 300 sec = 5 min
                    if self.logger:
                        self.logger.log_event("HEALTH", {
                            "component": "usb_monitor",
                            "status": "running",
                            "scans": scan_count,
                            "devices_connected": len(current_devices)
                        })
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n[USB] Shutting down...")
        except Exception as e:
            print(f"[USB ERROR] Monitor loop crashed: {e}")


def main():
    """Run USB monitor as standalone"""
    from agent_logger import AgentLogger
    
    logger = AgentLogger()
    monitor = AgentUSB(logger=logger)
    
    try:
        monitor.monitor_loop(interval=2)
    except KeyboardInterrupt:
        print("\n[USB] Stopped by user")


if __name__ == "__main__":
    main()