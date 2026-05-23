"""
agent_exam_controller.py - Unified exam enforcement controller

Responsibilities:
- Single decision point for all enforcement
- Mode-aware (EXAM = strict, LAB = permissive)
- Fast local database checks
- Confidence scoring for decisions
"""

import json
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime
from agent_threat_intelligence import ThreatIntelligence


class ExamBlockController:
    """Unified exam blocking and enforcement controller"""
    
    def __init__(self):
        """Initialize controller"""
        self.threat_db = ThreatIntelligence()
        self.mode = self._get_mode()
        self.policy = self._get_policy()
        self.decision_log = []
        
        print(f"[EXAM-CONTROLLER] Initialized (Mode: {self.mode})")
    
    def _get_mode(self) -> str:
        """Get current operating mode"""
        try:
            mode_file = Path("data/agent_mode.json")
            if mode_file.exists():
                with open(mode_file) as f:
                    data = json.load(f)
                    return data.get("mode", "LAB")
        except:
            pass
        return "LAB"
    
    def _get_policy(self) -> Dict:
        """Get enforcement policy"""
        try:
            policy_file = Path("data/agent_policy.json")
            if policy_file.exists():
                with open(policy_file) as f:
                    return json.load(f)
        except:
            pass
        
        return self._default_policy()
    
    def _default_policy(self) -> Dict:
        """Default restrictive policy"""
        return {
            "block_mass_storage": True,
            "allow_hid": True,
            "block_ai_tools": True,
            "block_social_media": True,
            "block_vpn": True,
            "block_proxy": True,
        }
    
    # ============ DOMAIN/URL CHECKS ============
    
    def check_domain_access(self, domain: str) -> Dict:
        """
        Check if domain access is allowed
        
        Args:
            domain: Domain to check (e.g., "chat.openai.com")
            
        Returns:
            {
                "allowed": bool,
                "confidence": int (0-100),
                "reason": str,
                "action": str ("allow", "block", "escalate"),
                "source": str ("local_db", "allowlist", "policy", "gemini"),
                "cost": float
            }
        """
        
        # EXAM mode: everything suspicious blocked
        if self.mode == "EXAM":
            # Check allowlist first
            is_allowed, conf = self.threat_db.is_domain_allowed(domain)
            if is_allowed:
                return self._decision(True, 100, "ALLOWED", "allow", "allowlist", 0)
            
            # Check blocklist
            is_blocked, conf = self.threat_db.is_domain_blocked(domain)
            if is_blocked:
                return self._decision(False, 100, "AI_TOOL_BLOCKED", "block", "local_db", 0)
            
            # In EXAM: unknown domains are blocked
            return self._decision(False, 75, "EXAM_MODE_UNKNOWN", "block", "policy", 0)
        
        # LAB mode: log suspicious but allow (educational)
        else:
            # Check allowlist first
            is_allowed, conf = self.threat_db.is_domain_allowed(domain)
            if is_allowed:
                return self._decision(True, 100, "ALLOWLIST", "allow", "allowlist", 0)
            
            # Check blocklist - LOG but ALLOW in LAB
            is_blocked, conf = self.threat_db.is_domain_blocked(domain)
            if is_blocked:
                return self._decision(True, 100, "BLOCKLIST_DETECTED_LAB_MODE", "log", "local_db", 0)
            
            # Unknown: allow in LAB but log
            return self._decision(True, 50, "LAB_MODE_UNKNOWN", "log", "policy", 0)
    
    # ============ PROCESS CHECKS ============
    
    def check_process_execution(self, process_name: str, process_path: str = None) -> Dict:
        """
        Check if process can execute
        
        Args:
            process_name: Process executable name (e.g., "tor.exe")
            process_path: Full path to process
            
        Returns:
            Decision dict
        """
        
        # Check if VPN tool
        is_vpn, conf = self.threat_db.is_vpn_tool(process_name)
        if is_vpn:
            if self.mode == "EXAM":
                return self._decision(False, 100, "VPN_TOOL_BLOCKED", "block", "local_db", 0)
            else:
                return self._decision(True, 100, "VPN_TOOL_DETECTED_LAB", "log", "local_db", 0)
        
        # Check blocklist
        is_blocked, conf = self.threat_db.is_process_blocked(process_name)
        if is_blocked:
            if self.mode == "EXAM":
                return self._decision(False, 100, "BLOCKED_PROCESS", "block", "local_db", 0)
            else:
                return self._decision(True, 100, "BLOCKED_PROCESS_LAB", "log", "local_db", 0)
        
        # EXAM mode: suspicious processes block
        if self.mode == "EXAM":
            suspicious_keywords = ["proxy", "tor", "vpn", "anonymize", "bypass", "hacktool"]
            for keyword in suspicious_keywords:
                if keyword in process_name.lower():
                    return self._decision(False, 85, "SUSPICIOUS_PROCESS", "block", "policy", 0)
            
            # System processes allowed
            system_paths = ["system32", "windows", "program files", "c:\\windows"]
            if process_path:
                if any(path.lower() in process_path.lower() for path in system_paths):
                    return self._decision(True, 90, "SYSTEM_PROCESS", "allow", "policy", 0)
        
        # Default: allow unknown processes (with logging in LAB mode)
        if self.mode == "LAB":
            return self._decision(True, 50, "UNKNOWN_PROCESS_LAB", "log", "policy", 0)
        else:
            return self._decision(True, 50, "UNKNOWN_PROCESS_EXAM", "log", "policy", 0)
    
    # ============ USB CHECKS ============
    
    def check_usb_device(self, device_name: str, device_class: str = "unknown") -> Dict:
        """
        Check if USB device can be connected
        
        Args:
            device_name: Device name
            device_class: "mass_storage", "hid", "unknown"
            
        Returns:
            Decision dict
        """
        
        # HID allowed (keyboard, mouse)
        if device_class == "hid":
            return self._decision(True, 100, "HID_ALLOWED", "allow", "policy", 0)
        
        # Mass storage handling depends on mode
        if device_class == "mass_storage":
            if self.mode == "EXAM":
                return self._decision(False, 100, "MASS_STORAGE_BLOCKED", "block", "policy", 0)
            else:
                return self._decision(True, 100, "MASS_STORAGE_LAB", "log", "policy", 0)
        
        # EXAM mode: block unknown USB
        if self.mode == "EXAM":
            return self._decision(False, 85, "EXAM_UNKNOWN_USB", "block", "policy", 0)
        
        # LAB mode: allow unknown USB
        return self._decision(True, 50, "LAB_UNKNOWN_USB", "log", "policy", 0)
    
    # ============ DRIVER CHECKS ============
    
    def check_driver_installation(self, driver_name: str) -> Dict:
        """
        Check if driver installation is allowed
        
        Args:
            driver_name: Driver name
            
        Returns:
            Decision dict
        """
        
        # Check suspicious drivers (VPN adapters)
        is_suspicious, conf = self.threat_db.is_suspicious_driver(driver_name)
        if is_suspicious:
            if self.mode == "EXAM":
                return self._decision(False, 100, "VPN_ADAPTER", "block", "local_db", 0)
            else:
                return self._decision(True, 100, "VPN_ADAPTER_LAB", "log", "local_db", 0)
        
        # VPN-like names handling
        vpn_keywords = ["vpn", "tap", "hamachi", "proton", "nordvpn"]
        for keyword in vpn_keywords:
            if keyword in driver_name.lower():
                if self.mode == "EXAM":
                    return self._decision(False, 90, "VPN_DRIVER_NAME", "block", "policy", 0)
                else:
                    return self._decision(True, 90, "VPN_DRIVER_NAME_LAB", "log", "policy", 0)
        
        # Default: allow unknown drivers
        return self._decision(True, 70, "UNKNOWN_DRIVER", "log", "policy", 0)
    
    # ============ HELPER METHODS ============
    
    def _decision(self, allowed: bool, confidence: int, reason: str, 
                  action: str, source: str, cost: float) -> Dict:
        """Create decision object"""
        decision = {
            "allowed": allowed,
            "confidence": confidence,
            "reason": reason,
            "action": action,
            "source": source,
            "cost": cost,
            "timestamp": datetime.now().isoformat(),
            "mode": self.mode,
            "gemini_call": False
        }
        self.decision_log.append(decision)
        return decision
    
    def get_statistics(self) -> Dict:
        """Get decision statistics"""
        if not self.decision_log:
            return {
                "total_decisions": 0,
                "blocked": 0,
                "allowed": 0,
                "escalated": 0,
                "avg_confidence": 0
            }
        
        blocked = sum(1 for d in self.decision_log if not d["allowed"])
        allowed = sum(1 for d in self.decision_log if d["allowed"])
        escalated = sum(1 for d in self.decision_log if d["action"] == "escalate")
        
        avg_conf = sum(d["confidence"] for d in self.decision_log) / len(self.decision_log)
        
        return {
            "total_decisions": len(self.decision_log),
            "blocked": blocked,
            "allowed": allowed,
            "escalated": escalated,
            "blocked_rate": f"{blocked/len(self.decision_log)*100:.1f}%" if self.decision_log else "0%",
            "avg_confidence": f"{avg_conf:.1f}%"
        }
    
    def clear_logs(self):
        """Clear decision log"""
        self.decision_log = []
