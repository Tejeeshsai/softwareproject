"""
agent_logger.py - Append-only event logger for AURA-EDU Agent

Responsibilities:
- Log USB, Web, Process, Tamper, Sync events
- Store in SQLite (offline-safe)
- Queue events for cloud sync
- Export to CSV for admin dashboard

Design principles:
- Append-only (never delete logs from agent)
- Fail-safe (if DB locked, buffer in memory)
- No network calls (sync module handles upload)
"""

import sqlite3
import json
import uuid
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class AgentLogger:
    """Local event logger with offline-first design"""
    
    def __init__(self, db_path: str = "data/agent_logs.db"):
        """Initialize logger with SQLite backend"""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._device_id = None
        self._init_db()
    
    def _init_db(self):
        """Create logs table if not exists"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                device_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT NOT NULL,
                synced INTEGER DEFAULT 0,
                created_at INTEGER DEFAULT (strftime('%s', 'now'))
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_synced 
            ON events(synced, created_at)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_event_type 
            ON events(event_type, timestamp)
        """)
        
        conn.commit()
        conn.close()
    
    def get_device_id(self) -> str:
        """Get or generate persistent device identifier"""
        if self._device_id:
            return self._device_id
        
        device_id_file = Path("data/device_id.txt")
        
        if device_id_file.exists():
            try:
                self._device_id = device_id_file.read_text().strip()
                return self._device_id
            except Exception:
                pass
        
        mac_address = uuid.getnode()
        self._device_id = str(uuid.UUID(int=mac_address))
        
        device_id_file.parent.mkdir(parents=True, exist_ok=True)
        device_id_file.write_text(self._device_id)
        
        return self._device_id
    
    def log_event(self, event_type: str, event_data: Dict):
        """Log an event to local database"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO events (timestamp, device_id, event_type, event_data)
                VALUES (?, ?, ?, ?)
            """, (
                datetime.utcnow().isoformat(),
                self.get_device_id(),
                event_type,
                json.dumps(event_data)
            ))
            
            conn.commit()
            conn.close()
            
        except sqlite3.OperationalError as e:
            self._log_to_fallback(event_type, event_data)
        except Exception as e:
            print(f"[LOGGER ERROR] {e}")
    
    def _log_to_fallback(self, event_type: str, event_data: Dict):
        """Write to fallback file if SQLite is unavailable"""
        fallback_file = Path("data/fallback_logs.txt")
        fallback_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(fallback_file, "a") as f:
            f.write(json.dumps({
                "timestamp": datetime.utcnow().isoformat(),
                "device_id": self.get_device_id(),
                "event_type": event_type,
                "event_data": event_data
            }) + "\n")
    
    def get_unsynced_logs(self, limit: int = 100) -> List[Tuple]:
        """Retrieve logs that haven't been uploaded to cloud"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, timestamp, device_id, event_type, event_data
                FROM events 
                WHERE synced = 0
                ORDER BY created_at ASC
                LIMIT ?
            """, (limit,))
            
            logs = cursor.fetchall()
            conn.close()
            
            return logs
            
        except Exception as e:
            print(f"[LOGGER ERROR] Failed to fetch unsynced logs: {e}")
            return []
    
    def mark_synced(self, log_ids: List[int]):
        """Mark logs as successfully uploaded to cloud"""
        if not log_ids:
            return
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            cursor = conn.cursor()
            
            placeholders = ','.join('?' * len(log_ids))
            cursor.execute(
                f"UPDATE events SET synced = 1 WHERE id IN ({placeholders})",
                log_ids
            )
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"[LOGGER ERROR] Failed to mark synced: {e}")
    
    def export_to_csv(self, output_path: str, event_type: Optional[str] = None):
        """Export logs to CSV for admin dashboard"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            cursor = conn.cursor()
            
            if event_type:
                cursor.execute("""
                    SELECT timestamp, device_id, event_type, event_data
                    FROM events
                    WHERE event_type = ?
                    ORDER BY created_at DESC
                """, (event_type,))
            else:
                cursor.execute("""
                    SELECT timestamp, device_id, event_type, event_data
                    FROM events
                    ORDER BY created_at DESC
                """)
            
            logs = cursor.fetchall()
            conn.close()
            
            with open(output_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Device ID', 'Event Type', 'Event Data'])
                writer.writerows(logs)
            
            print(f"[LOGGER] Exported {len(logs)} logs to {output_path}")
            
        except Exception as e:
            print(f"[LOGGER ERROR] Failed to export CSV: {e}")