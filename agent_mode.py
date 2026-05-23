"""
agent_mode.py - Mode management for AURA-EDU Agent

Responsibilities:
- Get current mode (LAB or EXAM)
- Switch between modes
- Persist mode to local file

Design principles:
- Single source of truth for mode
- Simple get/set interface
- File-based storage (survives reboot)
"""

import json
from pathlib import Path
from typing import Literal

ModeType = Literal["LAB", "EXAM"]


class AgentMode:
    """Manages agent operating mode"""
    
    def __init__(self, mode_file: str = "data/agent_mode.json"):
        """
        Initialize mode manager
        
        Args:
            mode_file: Path to mode configuration file
        """
        self.mode_file = Path(mode_file)
        self.mode_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize with default mode if file doesn't exist
        if not self.mode_file.exists():
            self.set_mode("LAB")
        
        print(f"[MODE] Initialized - Current mode: {self.get_current_mode()}")
    
    def get_current_mode(self) -> ModeType:
        """
        Get current operating mode
        
        Returns:
            'LAB' or 'EXAM'
        """
        try:
            with open(self.mode_file, 'r') as f:
                data = json.load(f)
                mode = data.get("mode", "LAB")
                
                # Validate mode value
                if mode not in ["LAB", "EXAM"]:
                    print(f"[MODE] Invalid mode '{mode}', defaulting to LAB")
                    return "LAB"
                
                return mode
                
        except FileNotFoundError:
            print(f"[MODE] Mode file not found, defaulting to LAB")
            return "LAB"
        except json.JSONDecodeError:
            print(f"[MODE] Corrupted mode file, defaulting to LAB")
            return "LAB"
        except Exception as e:
            print(f"[MODE ERROR] {e}, defaulting to LAB")
            return "LAB"
    
    def set_mode(self, mode: ModeType):
        """
        Set operating mode
        
        Args:
            mode: 'LAB' or 'EXAM'
        """
        if mode not in ["LAB", "EXAM"]:
            raise ValueError(f"Invalid mode: {mode}. Must be 'LAB' or 'EXAM'")
        
        try:
            data = {
                "mode": mode,
                "updated_at": self._get_timestamp()
            }
            
            with open(self.mode_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            print(f"[MODE] Mode set to: {mode}")
            
        except Exception as e:
            print(f"[MODE ERROR] Failed to set mode: {e}")
            raise
    
    def is_exam_mode(self) -> bool:
        """
        Check if currently in exam mode
        
        Returns:
            True if in EXAM mode, False otherwise
        """
        return self.get_current_mode() == "EXAM"
    
    def is_lab_mode(self) -> bool:
        """
        Check if currently in lab mode
        
        Returns:
            True if in LAB mode, False otherwise
        """
        return self.get_current_mode() == "LAB"
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.utcnow().isoformat()


def main():
    """Test mode management"""
    mode = AgentMode()
    
    print(f"\nCurrent mode: {mode.get_current_mode()}")
    print(f"Is exam mode: {mode.is_exam_mode()}")
    print(f"Is lab mode: {mode.is_lab_mode()}")
    
    # Test mode switching
    print("\nSwitching to EXAM mode...")
    mode.set_mode("EXAM")
    print(f"Current mode: {mode.get_current_mode()}")
    
    print("\nSwitching back to LAB mode...")
    mode.set_mode("LAB")
    print(f"Current mode: {mode.get_current_mode()}")


if __name__ == "__main__":
    main()