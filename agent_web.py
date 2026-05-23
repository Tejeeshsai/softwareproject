"""
agent_web.py - Web filtering for AURA-EDU Agent

Responsibilities:
- Block AI tools (ChatGPT, Claude, Gemini, etc.)
- Block social media, streaming, gaming sites
- Category-based blocking
- DNS-level blocking (hosts file)
- Offline-first (local blocklist)

Design principles:
- DNS hijacking (redirect to 127.0.0.1)
- Persistent blocking (survives reboot)
- Mode-aware (LAB = log, EXAM = block)
- Fast lookup (hash set)
"""

import os
import time
import socket
from pathlib import Path
from typing import Set, List, Dict, Optional
from agent_logger import AgentLogger


class AgentWeb:
    """Web filtering and blocking"""
    
    def __init__(self, logger: AgentLogger = None):
        """
        Initialize web filter
        
        Args:
            logger: Logger instance for event logging
        """
        self.logger = logger or AgentLogger()
        
        # Hosts file path (Windows and Unix)
        if os.name == 'nt':
            self.hosts_file = Path("C:\\Windows\\System32\\drivers\\etc\\hosts")
        else:
            self.hosts_file = Path("/etc/hosts")
        
        # Backup original hosts file
        self.hosts_backup = Path("data/hosts.backup")
        
        # Category-based blocklists
        self.ai_tools = {
            # ChatGPT
            "chat.openai.com",
            "chatgpt.com",
            "openai.com",
            
            # Claude
            "claude.ai",
            "anthropic.com",
            
            # Gemini
            "gemini.google.com",
            "bard.google.com",
            
            # Copilot
            "copilot.microsoft.com",
            "bing.com/chat",
            
            # Other AI
            "perplexity.ai",
            "you.com",
            "phind.com",
            "poe.com",
            "character.ai",
            "midjourney.com",
            "beta.elevenlabs.io",
        }
        
        self.social_media = {
            "facebook.com", "www.facebook.com", "m.facebook.com",
            "instagram.com", "www.instagram.com",
            "twitter.com", "x.com", "www.twitter.com",
            "snapchat.com", "www.snapchat.com",
            "tiktok.com", "www.tiktok.com",
            "reddit.com", "www.reddit.com",
            "discord.com", "www.discord.com",
            "whatsapp.com", "web.whatsapp.com",
            "telegram.org", "web.telegram.org",
        }
        
        self.streaming = {
            "youtube.com", "www.youtube.com", "m.youtube.com",
            "netflix.com", "www.netflix.com",
            "twitch.tv", "www.twitch.tv",
            "spotify.com", "www.spotify.com",
            "hulu.com", "www.hulu.com",
            "disneyplus.com", "www.disneyplus.com",
            "primevideo.com", "www.amazon.com/prime",
        }
        
        self.gaming = {
            "steam.com", "store.steampowered.com",
            "epicgames.com", "www.epicgames.com",
            "roblox.com", "www.roblox.com",
            "minecraft.net", "www.minecraft.net",
            "ea.com", "www.ea.com",
            "battle.net", "www.blizzard.com",
        }
        
        # Combine all blocklists
        self.blocked_domains: Set[str] = set()
        
        # Track what's currently blocked in hosts file
        self.currently_blocked: Set[str] = set()
        
        print(f"[WEB] Initialized")
        print(f"[WEB] AI tools: {len(self.ai_tools)} domains")
        print(f"[WEB] Social media: {len(self.social_media)} domains")
        print(f"[WEB] Streaming: {len(self.streaming)} domains")
        print(f"[WEB] Gaming: {len(self.gaming)} domains")
    
    def get_mode(self) -> str:
        """
        Get current agent mode
        
        Returns:
            'LAB' or 'EXAM'
        """
        mode_file = Path("data/agent_mode.json")
        
        if mode_file.exists():
            try:
                import json
                with open(mode_file) as f:
                    data = json.load(f)
                    return data.get("mode", "EXAM")
            except:
                pass
        
        return "EXAM"
    
    def load_policy(self) -> Dict:
        """
        Load blocking policy from file
        
        Returns:
            Policy dictionary
        """
        policy_file = Path("data/agent_policy.json")
        
        default_policy = {
            "block_ai_tools": True,
            "block_social_media": True,
            "block_streaming": True,
            "block_gaming": False,
            "custom_domains": []
        }
        
        if policy_file.exists():
            try:
                import json
                with open(policy_file) as f:
                    return json.load(f)
            except:
                pass
        
        return default_policy
    
    def update_blocklist(self):
        """
        Update blocked domains based on current policy
        """
        policy = self.load_policy()
        
        self.blocked_domains.clear()
        
        # Add categories based on policy
        if policy.get("block_ai_tools", True):
            self.blocked_domains.update(self.ai_tools)
        
        if policy.get("block_social_media", True):
            self.blocked_domains.update(self.social_media)
        
        if policy.get("block_streaming", True):
            self.blocked_domains.update(self.streaming)
        
        if policy.get("block_gaming", False):
            self.blocked_domains.update(self.gaming)
        
        # Add custom domains
        custom = policy.get("custom_domains", [])
        if custom:
            self.blocked_domains.update(custom)
        
        print(f"[WEB] Updated blocklist: {len(self.blocked_domains)} domains")
    
    def backup_hosts_file(self):
        """
        Backup original hosts file before modification
        """
        if not self.hosts_backup.exists():
            try:
                self.hosts_backup.parent.mkdir(parents=True, exist_ok=True)
                
                if self.hosts_file.exists():
                    content = self.hosts_file.read_text()
                    self.hosts_backup.write_text(content)
                    print(f"[WEB] Backed up hosts file")
            except PermissionError:
                print(f"[WEB ERROR] Permission denied backing up hosts file")
                print(f"[WEB ERROR] Run as Administrator!")
            except Exception as e:
                print(f"[WEB ERROR] Failed to backup hosts: {e}")
    
    def read_hosts_file(self) -> List[str]:
        """
        Read current hosts file content
        
        Returns:
            List of lines in hosts file
        """
        try:
            if self.hosts_file.exists():
                with open(str(self.hosts_file), 'r', encoding='utf-8') as f:
                    return f.read().splitlines()
            return []
        except PermissionError:
            print(f"[WEB ERROR] Permission denied reading hosts file - need Administrator!")
            raise
        except Exception as e:
            print(f"[WEB ERROR] Failed to read hosts: {e}")
            raise
    
    def write_hosts_file(self, lines: List[str]):
        """
        Write content to hosts file
        
        Args:
            lines: List of lines to write
        """
        try:
            content = "\n".join(lines) + "\n"
            with open(str(self.hosts_file), 'w', encoding='utf-8') as f:
                f.write(content)
            
            print(f"[WEB] Successfully wrote {len(lines)} lines to hosts file")
            
            # Flush DNS cache (Windows)
            if os.name == 'nt':
                result = os.system("ipconfig /flushdns >nul 2>&1")
                if result == 0:
                    print(f"[WEB] DNS cache flushed")
            
        except PermissionError:
            print(f"[WEB ERROR] Permission denied writing hosts file - need Administrator!")
            raise
        except Exception as e:
            print(f"[WEB ERROR] Failed to write hosts: {e}")
            raise
    
    def apply_blocking(self, mode: str = "EXAM"):
        """
        Apply web blocking to hosts file
        
        Args:
            mode: Current agent mode (LAB or EXAM)
        """
        # Update blocklist from policy
        self.update_blocklist()
        
        if mode == "LAB":
            print(f"[WEB] LAB MODE: Would block {len(self.blocked_domains)} domains (not applied)")
            
            # Log what would be blocked
            self.logger.log_event("WEB", {
                "action": "policy_loaded",
                "mode": "LAB",
                "domains_count": len(self.blocked_domains),
                "categories": {
                    "ai_tools": len(self.ai_tools.intersection(self.blocked_domains)),
                    "social_media": len(self.social_media.intersection(self.blocked_domains)),
                    "streaming": len(self.streaming.intersection(self.blocked_domains))
                }
            })
            return
        
        # Backup hosts file first
        self.backup_hosts_file()
        
        try:
            # Read current hosts file
            lines = self.read_hosts_file()
            
            # Remove old AURA blocks - look for AURA-EDU marker anywhere in line
            filtered_lines = []
            for line in lines:
                if "AURA-EDU" not in line:
                    filtered_lines.append(line)
            
            # Add AURA block section with all AI tools and blocked domains
            filtered_lines.append("")
            filtered_lines.append("# AURA-EDU BLOCKING - DO NOT EDIT")
            filtered_lines.append(f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            filtered_lines.append("")
            
            # Add blocked domains
            for domain in sorted(self.blocked_domains):
                filtered_lines.append(f"127.0.0.1 {domain} # AURA-EDU")
                self.currently_blocked.add(domain)
            
            filtered_lines.append("")
            filtered_lines.append("# END AURA-EDU BLOCKING")
            filtered_lines.append("")
            
            # Write back to hosts file
            self.write_hosts_file(filtered_lines)
            
            print(f"[WEB] Blocking applied: {len(self.blocked_domains)} domains blocked")
            
            # Log blocking action
            self.logger.log_event("WEB", {
                "action": "blocking_applied",
                "mode": "EXAM",
                "domains_blocked": len(self.blocked_domains),
                "ai_tools_blocked": len(self.ai_tools.intersection(self.blocked_domains))
            })
        
        except PermissionError:
            print(f"[WEB ERROR] ADMIN REQUIRED: Run VS Code/Terminal as Administrator!")
            print(f"[WEB ERROR] Right-click > Run as Administrator")
            raise
        except Exception as e:
            print(f"[WEB ERROR] Failed to apply blocking: {e}")
            raise
    
    def remove_blocking(self):
        """
        Remove all AURA blocking from hosts file
        """
        try:
            print(f"[WEB] Removing blocking from hosts file...")
            
            lines = self.read_hosts_file()
            
            # Remove all AURA-EDU lines
            filtered_lines = []
            for line in lines:
                if "AURA-EDU" not in line:
                    filtered_lines.append(line)
            
            self.write_hosts_file(filtered_lines)
            
            self.currently_blocked.clear()
            
            print(f"[WEB] Blocking removed successfully")
            
            # Log removal
            self.logger.log_event("WEB", {
                "action": "blocking_removed"
            })
        
        except PermissionError:
            print(f"[WEB ERROR] ADMIN REQUIRED: Run VS Code/Terminal as Administrator!")
            raise
        except Exception as e:
            print(f"[WEB ERROR] Failed to remove blocking: {e}")
            raise
    
    def test_blocking(self, domain: str) -> bool:
        """
        Test if a domain is blocked
        
        Args:
            domain: Domain to test
            
        Returns:
            True if blocked, False otherwise
        """
        try:
            ip = socket.gethostbyname(domain)
            
            if ip == "127.0.0.1":
                print(f"[WEB] ✅ {domain} is BLOCKED (resolves to {ip})")
                return True
            else:
                print(f"[WEB] ⚠️  {domain} is NOT blocked (resolves to {ip})")
                return False
                
        except socket.gaierror:
            print(f"[WEB] ⚠️  {domain} - DNS resolution failed")
            return False
    
    def monitor_loop(self, interval: int = 300):
        """
        Main monitoring loop
        
        Args:
            interval: Check interval in seconds (default: 5 minutes)
        """
        print(f"[WEB] Starting monitor loop (interval: {interval}s)")
        
        # Apply initial blocking
        mode = self.get_mode()
        self.apply_blocking(mode=mode)
        
        check_count = 0
        
        try:
            while True:
                check_count += 1
                
                # Re-check mode
                mode = self.get_mode()
                
                # Re-apply blocking (in case hosts file was modified)
                if mode == "EXAM":
                    self.apply_blocking(mode=mode)
                
                # Health log every 30 minutes
                if check_count % 6 == 0:  # 6 * 5 minutes = 30 minutes
                    self.logger.log_event("HEALTH", {
                        "component": "web_filter",
                        "status": "running",
                        "domains_blocked": len(self.currently_blocked)
                    })
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n[WEB] Shutting down...")
            
            # Remove blocking on shutdown (optional)
            # self.remove_blocking()


def main():
    """Run web filter as standalone"""
    logger = AgentLogger()
    web_filter = AgentWeb(logger)
    
    try:
        web_filter.monitor_loop(interval=300)
    except KeyboardInterrupt:
        print("\n[WEB] Stopped by user")
        # web_filter.remove_blocking()  # Uncomment to auto-remove on stop


if __name__ == "__main__":
    main()