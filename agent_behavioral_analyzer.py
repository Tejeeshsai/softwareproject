
"""
agent_behavioral_analyzer.py - Behavioral anomaly detection

Responsibilities:
- Detect suspicious patterns
- Track violation spikes
- Only trigger Gemini for truly ambiguous cases (~5%)
- Pattern analysis without API calls
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json


class BehavioralAnalyzer:
    """Behavioral anomaly detection"""
    
    def __init__(self):
        """Initialize analyzer"""
        self.violation_history = defaultdict(list)  # device_id -> list of violations
        self.patterns = defaultdict(int)  # pattern_name -> count
        
        # Thresholds
        self.SPIKE_THRESHOLD = 5  # violations in time window
        self.SPIKE_WINDOW = 300  # 5 minutes
        self.SUSPICIOUS_SEQUENCE_THRESHOLD = 0.7
        
        print("[BEHAVIORAL-ANALYZER] Initialized")
    
    def log_violation(self, device_id: str, violation_type: str, 
                     violation_data: Dict, confidence: int = 50):
        """
        Log a violation event
        
        Args:
            device_id: Device identifier
            violation_type: Type of violation
            violation_data: Data about violation
            confidence: Initial confidence (0-100)
        """
        event = {
            "timestamp": datetime.now(),
            "type": violation_type,
            "data": violation_data,
            "confidence": confidence
        }
        self.violation_history[device_id].append(event)
    
    def detect_spike(self, device_id: str) -> Dict:
        """
        Detect violation spike
        
        Args:
            device_id: Device to analyze
            
        Returns:
            {
                "spike_detected": bool,
                "violation_count": int,
                "time_window": int,
                "severity": str ("low", "medium", "high"),
                "recommendation": str
            }
        """
        violations = self.violation_history[device_id]
        
        if len(violations) < 2:
            return {
                "spike_detected": False,
                "violation_count": len(violations),
                "severity": "low"
            }
        
        # Check last N minutes for violations
        now = datetime.now()
        recent_violations = [
            v for v in violations 
            if (now - v["timestamp"]).total_seconds() < self.SPIKE_WINDOW
        ]
        
        spike_detected = len(recent_violations) >= self.SPIKE_THRESHOLD
        
        severity = "low"
        if len(recent_violations) >= 10:
            severity = "high"
        elif len(recent_violations) >= self.SPIKE_THRESHOLD:
            severity = "medium"
        
        return {
            "spike_detected": spike_detected,
            "violation_count": len(recent_violations),
            "time_window": self.SPIKE_WINDOW,
            "severity": severity,
            "recommendation": "escalate" if severity == "high" else "log",
            "violations": recent_violations
        }
    
    def detect_suspicious_sequence(self, device_id: str) -> Dict:
        """
        Detect suspicious tool sequences
        
        Returns:
            {
                "sequence_detected": bool,
                "pattern": str,
                "confidence": float (0-1),
                "tools": list
            }
        """
        violations = self.violation_history[device_id]
        
        if len(violations) < 2:
            return {
                "sequence_detected": False,
                "confidence": 0.0
            }
        
        # Get last 10 violations
        recent = violations[-10:]
        tool_names = [v["data"].get("name", v["type"]) for v in recent]
        
        # Define suspicious sequences
        suspicious_patterns = [
            # Reconnaissance + Exfiltration
            {
                "pattern": "port_scanner_then_vpn",
                "tools": ["port_scanner", "nmap", "netstat"],
                "followed_by": ["tor", "vpn", "proxy"],
                "confidence": 0.85
            },
            # Network monitoring + VPN
            {
                "pattern": "network_monitor_then_vpn",
                "tools": ["wireshark", "tcpdump", "network_monitor"],
                "followed_by": ["tor", "vpn"],
                "confidence": 0.80
            },
            # Multiple bypass tools
            {
                "pattern": "multiple_bypass_tools",
                "tools": ["tor", "vpn", "psiphon", "proxy"],
                "confidence": 0.90
            }
        ]
        
        for pat in suspicious_patterns:
            match_count = sum(1 for tool in pat["tools"] if any(tool in str(t).lower() for t in tool_names))
            
            if match_count >= len(pat["tools"]) * 0.7:  # 70% match
                return {
                    "sequence_detected": True,
                    "pattern": pat["pattern"],
                    "confidence": pat["confidence"],
                    "tools": [t for t in tool_names if any(kw in str(t).lower() for kw in pat["tools"])],
                    "recommendation": "escalate"
                }
        
        return {
            "sequence_detected": False,
            "confidence": 0.0
        }
    
    def detect_unusual_time_pattern(self, device_id: str) -> Dict:
        """
        Detect unusual time patterns
        
        Returns:
            {
                "unusual_time": bool,
                "time_of_day": str,
                "violation_count": int,
                "severity": str
            }
        """
        violations = self.violation_history[device_id]
        
        if not violations:
            return {"unusual_time": False}
        
        now = datetime.now()
        hour = now.hour
        
        # Unusual hours: midnight to 5am (0-5)
        if 0 <= hour <= 5:
            recent_violations = len([
                v for v in violations 
                if v["timestamp"].hour == hour
            ])
            
            if recent_violations > 0:
                return {
                    "unusual_time": True,
                    "time_of_day": f"{hour:02d}:00",
                    "violation_count": recent_violations,
                    "severity": "high" if recent_violations > 2 else "medium",
                    "recommendation": "alert_admin"
                }
        
        return {"unusual_time": False}
    
    def calculate_risk_score(self, device_id: str) -> Dict:
        """
        Calculate overall device risk score
        
        Returns:
            {
                "risk_score": float (0-100),
                "risk_level": str ("low", "medium", "high", "critical"),
                "factors": list,
                "recommendation": str
            }
        """
        spike_analysis = self.detect_spike(device_id)
        sequence_analysis = self.detect_suspicious_sequence(device_id)
        time_analysis = self.detect_unusual_time_pattern(device_id)
        
        risk_score = 0.0
        factors = []
        
        # Spike factor (0-40 points)
        if spike_analysis["spike_detected"]:
            if spike_analysis["severity"] == "high":
                risk_score += 40
                factors.append(f"High violation spike ({spike_analysis['violation_count']} in {spike_analysis['time_window']}s)")
            elif spike_analysis["severity"] == "medium":
                risk_score += 25
                factors.append(f"Medium violation spike ({spike_analysis['violation_count']} violations)")
        
        # Sequence factor (0-35 points)
        if sequence_analysis["sequence_detected"]:
            risk_score += int(sequence_analysis["confidence"] * 35)
            factors.append(f"Suspicious sequence: {sequence_analysis['pattern']}")
        
        # Time factor (0-25 points)
        if time_analysis.get("unusual_time"):
            if time_analysis["severity"] == "high":
                risk_score += 25
                factors.append(f"Unusual time: {time_analysis['time_of_day']}")
            elif time_analysis["severity"] == "medium":
                risk_score += 15
                factors.append(f"Unusual time: {time_analysis['time_of_day']}")
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = "critical"
            recommendation = "immediately_escalate_to_admin"
        elif risk_score >= 60:
            risk_level = "high"
            recommendation = "escalate_to_admin"
        elif risk_score >= 40:
            risk_level = "medium"
            recommendation = "monitor_closely"
        else:
            risk_level = "low"
            recommendation = "log_only"
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "factors": factors,
            "recommendation": recommendation,
            "needs_gemini": risk_score >= 50 and risk_score < 70  # Ambiguous range
        }
    
    def should_call_gemini(self, device_id: str) -> Dict:
        """
        Decide if Gemini should be called
        
        Only calls Gemini for truly ambiguous cases (~5%)
        
        Returns:
            {
                "call_gemini": bool,
                "reason": str,
                "context": dict
            }
        """
        risk_analysis = self.calculate_risk_score(device_id)
        
        # Call Gemini for ambiguous cases (50-70 confidence range)
        if 50 <= risk_analysis["risk_score"] < 70:
            return {
                "call_gemini": True,
                "reason": "ambiguous_case",
                "confidence_range": "50-70",
                "context": {
                    "risk_score": risk_analysis["risk_score"],
                    "factors": risk_analysis["factors"],
                    "violations": self._get_recent_violations(device_id),
                    "timestamp": datetime.now().isoformat()
                }
            }
        
        return {
            "call_gemini": False,
            "reason": "high_or_low_confidence",
            "risk_score": risk_analysis["risk_score"]
        }
    
    def _get_recent_violations(self, device_id: str, count: int = 10) -> List:
        """Get last N violations for context"""
        violations = self.violation_history[device_id][-count:]
        return [
            {
                "timestamp": v["timestamp"].isoformat(),
                "type": v["type"],
                "confidence": v["confidence"]
            }
            for v in violations
        ]
    
    def get_device_summary(self, device_id: str) -> Dict:
        """Get full device analysis summary"""
        violations = self.violation_history[device_id]
        spike = self.detect_spike(device_id)
        sequence = self.detect_suspicious_sequence(device_id)
        risk = self.calculate_risk_score(device_id)
        gemini_decision = self.should_call_gemini(device_id)
        
        return {
            "device_id": device_id,
            "total_violations": len(violations),
            "spike_analysis": spike,
            "sequence_analysis": sequence,
            "risk_analysis": risk,
            "gemini_decision": gemini_decision,
            "last_violation": violations[-1]["timestamp"].isoformat() if violations else None
        }
    
    def clear_history(self, device_id: str = None):
        """Clear violation history"""
        if device_id:
            self.violation_history[device_id] = []
        else:
            self.violation_history.clear()
