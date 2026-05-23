# AURA-EDU Agent Main - Full System Deployment

## Overview

The **demo_app.py** is an educational UI that shows decision logic. For **real enforcement** and actual blocking, use **agent_main.py** which starts the complete AURA-EDU system with all enforcement modules.

---

## Difference: Demo vs Real System

| Aspect | demo_app.py | agent_main.py |
|--------|------------|---------------|
| **Purpose** | Educational UI - shows decisions | Real enforcement - actually blocks |
| **What it does** | Shows numbers, makes decisions | Blocks domains, processes, USB devices |
| **Admin required** | Yes (for demo blocking) | Yes (for real enforcement) |
| **Network blocking** | Modifies hosts file (if admin) | Modifies hosts file + monitors |
| **Process blocking** | Shows decisions only | Blocks via registry/Windows |
| **USB blocking** | Shows decisions only | Blocks via registry |
| **Monitoring** | Static UI refresh | Continuous background monitoring |
| **Threads** | Flask web server | Logger, Watchdog, Sync, Web Filter threads |

---

## Running agent_main.py (Real System)

### Step 1: Open Terminal as Administrator

**On Windows:**
1. Right-click Command Prompt or PowerShell
2. Select "Run as administrator"
3. Accept the UAC prompt

Or use VS Code:
1. Press `Ctrl+Shift+P`
2. Search for "Terminal: Create New Terminal (With Administrator Privilege)"

### Step 2: Navigate to Project

```powershell
cd f:\AURA-EDU-FINAL
```

### Step 3: Run the Agent

```powershell
python agent_main.py
```

### Expected Output

```
============================================================
🛡️  AURA-EDU AGENT - Starting...
============================================================

[LOGGER] Initialized
[WATCHDOG] Initialized (Monitoring: python.exe)
[SYNC] Initialized (Target: http://localhost:5000)

[EXAM-CONTROLLER] Initialized (Mode: LAB)
[WEB] Initialized
[THREAT-DB] Loaded

[AGENT-MAIN] All modules started
[AGENT-MAIN] Logger thread: RUNNING
[AGENT-MAIN] Watchdog thread: RUNNING
[AGENT-MAIN] Sync thread: RUNNING
```

Agent is now running continuously in the background.

---

## How agent_main.py Works

### 1. **AgentLogger** (Continuous Logging)
- Logs all events to `data/agent_audit.log`
- Monitors what's happening in real-time
- File persists across reboots

### 2. **AgentWatchdog** (Continuous Monitoring)
- Watches for suspicious processes
- Monitors USB device connections
- Blocks based on current mode (EXAM/LAB)
- Runs every 5 seconds

### 3. **AgentSync** (Cloud Integration)
- Syncs decisions with central server
- Uploads decision log periodically
- Receives policy updates from cloud
- Enables remote monitoring

### 4. **AgentWeb** (Domain Blocking)
- Modifies Windows hosts file
- Blocks domains listed in policy
- Blocks Ai tools, social media, streaming
- Survives system reboot

### 5. **ExamBlockController** (Decision Engine)
- Makes yes/no decisions on all threats
- Uses threat database for fast lookup
- Confidence scoring for ambiguous cases
- Hands off to other modules for enforcement

---

## Switching Between Modes

### Via Command Line (Real System)

```powershell
python agent_mode.py --mode EXAM
```

Or:

```powershell
python agent_mode.py --mode LAB
```

Checks the file `data/agent_mode.json` - all running modules read this automatically.

### Via Demo UI

Click "Switch Mode (LAB ↔ EXAM)" button - but this only works if running as administrator.

---

## Configuration Files

### agent_mode.json
Current operating mode
```json
{
  "mode": "LAB",
  "updated_at": "2026-02-16T10:30:00.000000"
}
```

### agent_policy.json
What gets blocked
```json
{
  "block_ai_tools": true,
  "block_social_media": true,
  "block_streaming": true,
  "block_vpn": true,
  "block_usb_storage": true,
  "custom_domains": [
    "example.com",
    "badsite.com"
  ]
}
```

### Device ID
File: `data/device_id.txt` - identifies this computer in cloud sync

---

## Viewing Real System Logs

### Audit Log
```powershell
Get-Content data/agent_audit.log -Tail 50
```

### Decision Log CSV
```powershell
type data/test_export.csv
```

---

## Blocking Categories (EXAM Mode)

### AI Tools
- chat.openai.com, chatgpt.com
- claude.ai, anthropic.com
- gemini.google.com, bard.google.com
- microsoft.com/copilot
- perplexity.ai, you.com

### Social Media
- facebook.com, instagram.com, twitter.com, x.com
- snapchat.com, tiktok.com, reddit.com
- discord.com, whatsapp.com, telegram.org

### Streaming
- youtube.com, netflix.com, twitch.tv
- spotify.com, hulu.com, disneyplus.com

### Hardware
- USB Mass Storage devices
- VPN adapters (TAP, Hamachi, ProtonVPN)

### Processes
- tor.exe, vpn tools
- Proxy applications
- Suspicious executables

---

## Troubleshooting

### "Permission Denied" Error
**Problem:** Trying to block domains without admin rights

**Solution:**
```powershell
# Run Terminal as Administrator first
python agent_main.py
```

### Changes Not Applying
**Problem:** Running demo_app.py without admin rights

**Problem:** Mode file exists but agent isn't reading it

**Solution:**
```powershell
# Check current mode
Get-Content data/agent_mode.json

# Force update mode
python agent_mode.py --mode EXAM

# Verify all agents reading new mode
python agent_main.py
```

### Hosts File Corrupted
**Problem:** Domains blocked even after clearing, or weird network errors

**Solution:** Restore backup
```powershell
# AURA-EDU keeps a backup
Copy-Item data/hosts.backup C:\Windows\System32\drivers\etc\hosts -Force

# Or manually check hosts file
notepad C:\Windows\System32\drivers\etc\hosts
```

---

## Real vs Demo Comparison

### Real System (agent_main.py)
✅ **Actually blocks** domains - you physically cannot access them
✅ **Blocks USB** - devices rejected by Windows
✅ **Blocks processes** - can't run suspicious executables
✅ **Survives reboot** - hosts file modification persists
✅ **Continuous monitoring** - runs 24/7 in background
✅ **Cloud sync** - uploads to server for audit trail

### Demo System (demo_app.py)
✅ **Shows decisions** - tells you what WOULD be blocked
✅ **Learns the logic** - understand the decision framework
✅ **No disruption** - doesn't actually block anything
✅ **Easy to test** - no admin required (but blocking does)
✅ **Visual feedback** - see all decisions in real-time
❌ **No real enforcement** - domains still accessible

---

## Running Both Side-by-Side

You can run BOTH simultaneously:

**Terminal 1 (as Administrator):**
```powershell
python agent_main.py
```

**Terminal 2 (any privileges):**
```powershell
python demo_app.py
```

Then open: http://localhost:5000

The demo UI will show what the real agent is doing, and if you have admin, both will enforce blocks together.

---

## Next Steps

1. **Test in LAB mode first**
   - Switches don't block anything
   - Safe to understand the system

2. **Switch to EXAM mode**
   - If admin, begins real enforcement
   - Open http://localhost:5000 to watch decisions

3. **Try to access blocked sites**
   - In Chrome: type chat.openai.com
   - Should refuse to load or timeout
   - Check Windows hosts file to verify modification

4. **Monitor logs**
   - `data/agent_audit.log` shows all events
   - Real timestamps of blocks/allows
   - Can share with administrators

---

## Architecture Diagram

```
agent_main.py (Orchestrator)
    ├── AgentLogger (logs all events)
    ├── AgentWatchdog (monitors continuously)
    │   ├── Checks processes every 5 seconds
    │   ├── Checks USB devices
    │   └── Calls ExamBlockController for decisions
    ├── AgentSync (cloud upload)
    │   └── Sends decision log to server
    └── ExamBlockController (decision engine)
        ├── Checks domain (→ AgentWeb)
        ├── Checks process (→ AgentProcess)
        ├── Checks USB (→ AgentUSB)
        └── Logs decision (→ AgentLogger)

AgentWeb (Domain Blocking)
├── Reads current policy (agent_policy.json)
├── Updates blocklist
└── Modifies hosts file (requires admin)

AgentUSB (Device Blocking)
└── Modifies Windows registry

AgentProcess (Executable Blocking)
└── Uses Windows API to prevent execution
```

---

## File Structure

```
AURA-EDU-FINAL/
├── agent_main.py              ← Real enforcement system
├── agent_exam_controller.py    ← Decision maker
├── agent_threat_intelligence.py ← Database
├── agent_web.py               ← Domain blocking
├── agent_usb.py               ← USB blocking
├── agent_process.py           ← Process blocking
├── agent_watchdog.py          ← Continuous monitor
├── agent_sync.py              ← Cloud sync
├── agent_logger.py            ← Event logging
│
├── demo_app.py                ← Educational demo UI
├── demo_requirements.txt       ← Demo dependencies
│
├── data/
│   ├── agent_mode.json        ← Current mode
│   ├── agent_policy.json      ← Blocking policy
│   ├── agent_audit.log        ← Event history
│   ├── device_id.txt          ← Device identifier
│   └── hosts.backup           ← Backup hosts file
│
└── tests/
    ├── test_main.py
    ├── test_real_blocking_admin.py
    └── ...
```

---

## Questions?

- **Is the demo actually blocking?** No - it's a UI showing decisions only. Use agent_main.py for real blocking.
- **Do I need admin for demo?** Only if you want demo to actually block. Without it, numbers still increase but domains stay accessible.
- **What gets blocked in EXAM?** AI tools, social media, streaming, USB, VPN. See blocking categories above.
- **Does it surviveReboot?** Yes - hosts file modification persists. Even if agent stops, blocks remain until admin removes them.
- **How do I turn off blocking?** Switch back to LAB mode, or manually edit C:\Windows\System32\drivers\etc\hosts

---

Last updated: 2026-02-16
