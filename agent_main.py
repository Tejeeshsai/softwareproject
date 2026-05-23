"""
agent_main.py - Main orchestrator for AURA-EDU Agent

Responsibilities:
- Initialize all modules
- Start enforcement threads
- Coordinate logger, watchdog, sync
- Health monitoring
- Graceful shutdown

Design principles:
- Each module runs in its own thread
- Main thread monitors health
- Clean shutdown on Ctrl+C
- No single point of failure
"""

import sys
import time
import threading
import signal
from pathlib import Path

# Import all agent modules
from agent_logger import AgentLogger
from agent_watchdog import AgentWatchdog
from agent_sync import AgentSync


class AuraAgent:
    """Main agent orchestrator"""
    
    def __init__(self):
        """Initialize all agent modules"""
        print("=" * 60)
        print("🛡️  AURA-EDU AGENT - Starting...")
        print("=" * 60)
        print()
        
        # Core infrastructure
        self.logger = AgentLogger()
        self.watchdog = AgentWatchdog(
            agent_process_name="python.exe",
            agent_script_path="agent_main.py"
        )
        self.sync = AgentSync(
            cloud_url="http://localhost:5000",  # Change in production
            timeout=10
        )
        
        # Enforcement modules (placeholders for now)
        # TODO: Add when Amogh completes files 1-5
        # self.usb = AgentUSB(self.logger)
        # self.process = AgentProcess(self.logger)
        # self.web = AgentWeb(self.logger)
        
        # Thread references
        self.threads = []
        self.running = False
        
        print()
        print("✅ All modules initialized")
        print()
    
    def start(self):
        """Start all agent services"""
        print("🚀 Starting agent services...")
        print()
        
        self.running = True
        
        # Start watchdog (monitors agent health)
        watchdog_thread = threading.Thread(
            target=self.watchdog.monitor_loop,
            args=(5,),  # 5 second interval
            daemon=True,
            name="Watchdog"
        )
        watchdog_thread.start()
        self.threads.append(watchdog_thread)
        print("✅ Watchdog started")
        
        # Start sync (cloud communication)
        sync_thread = threading.Thread(
            target=self.sync.sync_loop,
            args=(60,),  # 60 second interval
            daemon=True,
            name="CloudSync"
        )
        sync_thread.start()
        self.threads.append(sync_thread)
        print("✅ Cloud sync started")
        
        # TODO: Start enforcement modules when available
        # usb_thread = threading.Thread(target=self.usb.monitor_loop, daemon=True)
        # process_thread = threading.Thread(target=self.process.monitor_loop, daemon=True)
        # web_thread = threading.Thread(target=self.web.monitor_loop, daemon=True)
        
        print()
        print("=" * 60)
        print("🛡️  AURA-EDU AGENT - RUNNING")
        print("=" * 60)
        print()
        print(f"📊 Active threads: {len(self.threads)}")
        print(f"📊 Device ID: {self.logger.get_device_id()[:16]}...")
        print()
        print("Press Ctrl+C to stop")
        print()
        
        # Log startup event
        self.logger.log_event("HEALTH", {
            "action": "agent_started",
            "threads": len(self.threads),
            "timestamp": time.time()
        })
        
        # Main loop - health monitoring
        self._health_monitor_loop()
    
    def _health_monitor_loop(self):
        """Monitor agent health in main thread"""
        last_health_log = time.time()
        
        try:
            while self.running:
                # Check thread health
                alive_threads = [t for t in self.threads if t.is_alive()]
                
                if len(alive_threads) < len(self.threads):
                    print("⚠️  WARNING: Some threads died!")
                    for t in self.threads:
                        if not t.is_alive():
                            print(f"   💀 Dead thread: {t.name}")
                
                # Log health status every 5 minutes
                if time.time() - last_health_log > 300:
                    self.logger.log_event("HEALTH", {
                        "action": "health_check",
                        "threads_alive": len(alive_threads),
                        "threads_total": len(self.threads),
                        "uptime": int(time.time() - last_health_log)
                    })
                    last_health_log = time.time()
                    print(f"💚 Health check OK ({len(alive_threads)}/{len(self.threads)} threads)")
                
                time.sleep(60)  # Check every minute
                
        except KeyboardInterrupt:
            print("\n\n⚠️  Shutdown signal received...")
            self.stop()
    
    def stop(self):
        """Gracefully stop all agent services"""
        print()
        print("🛑 Stopping agent services...")
        
        self.running = False
        
        # Log shutdown event
        self.logger.log_event("HEALTH", {
            "action": "agent_stopped",
            "timestamp": time.time()
        })
        
        # Wait for threads to finish (max 5 seconds)
        print("⏳ Waiting for threads to finish...")
        for thread in self.threads:
            thread.join(timeout=5)
        
        print("✅ Agent stopped cleanly")
        print()
        sys.exit(0)


def setup_signal_handlers(agent):
    """Setup graceful shutdown on Ctrl+C"""
    def signal_handler(sig, frame):
        agent.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def main():
    """Main entry point"""
    # Create agent
    agent = AuraAgent()
    
    # Setup signal handlers
    setup_signal_handlers(agent)
    
    # Start agent
    agent.start()


if __name__ == "__main__":
    main()