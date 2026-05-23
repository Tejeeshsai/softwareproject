#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
demo_app.py - Simple localhost demo of the agent system

Run: python demo_app.py
Then open: http://localhost:5000

Shows:
- Threat database loaded
- Exam blocking in real-time
- Behavioral analysis
- Decision logging
"""

from flask import Flask, render_template_string, request, jsonify, make_response
import json
import sys
import os
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from agent_exam_controller import ExamBlockController
from agent_behavioral_analyzer import BehavioralAnalyzer
from agent_threat_intelligence import ThreatIntelligence
from agent_web import AgentWeb
from agent_logger import AgentLogger

# Force UTF-8 encoding
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

app = Flask(__name__)

# Add no-cache headers to all responses
@app.after_request
def no_cache(response):
    response.cache_control.no_cache = True
    response.cache_control.no_store = True
    response.cache_control.must_revalidate = True
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Initialize agents
controller = ExamBlockController()
analyzer = BehavioralAnalyzer()
threat_db = ThreatIntelligence()
logger = AgentLogger()
web_filter = AgentWeb(logger)

# Demo state
current_mode = "LAB"
demo_violations = []
auto_test_enabled = True
auto_test_index = 0
scheduler = BackgroundScheduler()

# Test cases for auto-generation
AUTO_TEST_CASES = [
    ("ai", "ChatGPT Web Access", lambda: controller.check_domain_access("chat.openai.com")),
    ("vpn", "Tor.exe Process Startup", lambda: controller.check_process_execution("tor.exe", "C:\\AppData\\Tor\\tor.exe")),
    ("usb", "USB Mass Storage Insertion", lambda: controller.check_usb_device("SanDisk_Flash_Drive", "mass_storage")),
    ("unknown", "Unknown Executable", lambda: controller.check_process_execution("suspicious.exe", "C:\\Users\\Desktop\\suspicious.exe")),
]


def run_auto_test():
    """Run one auto-test iteration"""
    global controller, analyzer, current_mode, auto_test_enabled, auto_test_index
    
    if not auto_test_enabled:
        return
    
    try:
        # Pick test case in sequence
        test_type, scenario, decision_func = AUTO_TEST_CASES[auto_test_index % len(AUTO_TEST_CASES)]
        auto_test_index += 1
        
        # Ensure controller mode is synced
        controller.mode = current_mode
        
        # Execute test
        decision = decision_func()
        print(f"[AUTO-{test_type.upper()}] {scenario} | Mode: {current_mode} | Allowed: {decision['allowed']} | Confidence: {decision['confidence']}%")
        
        # Log violation
        analyzer.log_violation(
            "demo_device_001",
            scenario,
            {"type": test_type},
            confidence=decision["confidence"]
        )
        
        # Log to agent logger
        logger.log_event(f"AUTO_{test_type.upper()}", {
            "scenario": scenario,
            "allowed": decision["allowed"],
            "reason": decision["reason"],
            "confidence": decision["confidence"],
            "source": decision["source"],
            "mode": current_mode
        })
    except Exception as e:
        print(f"[AUTO-ERROR] Exception in auto_test: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


# Configure scheduler
scheduler.add_job(
    func=run_auto_test,
    trigger="interval",
    seconds=3,
    id='auto_test_job',
    name='Auto violation generator',
    replace_existing=True
)




HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>AURA-EDU Agent Demo</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #F8F8F8; color: #333333; min-height: 100vh; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        header { text-align: center; margin-bottom: 30px; border-bottom: 3px solid #FF8C00; padding-bottom: 20px; }
        h1 { color: #FF8C00; font-size: 32px; margin-bottom: 5px; text-shadow: 1px 1px 2px rgba(0,0,0,0.1); }
        .subtitle { color: #666666; font-size: 14px; }
        
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
        @media (max-width: 1200px) { .grid { grid-template-columns: 1fr; } }
        
        .card { background: #FFFFFF; border: 2px solid #FF8C00; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(255,140,0,0.15); }
        .card h2 { color: #FF8C00; font-size: 18px; margin-bottom: 15px; border-bottom: 2px solid #FF8C00; padding-bottom: 10px; }
        .card h3 { color: #FFA500; font-size: 14px; margin-top: 15px; margin-bottom: 8px; }
        
        .status-box { background: #F5F5F5; padding: 15px; border-radius: 5px; margin-bottom: 10px; font-size: 14px; font-family: monospace; border-left: 3px solid #FF8C00; }
        .status-good { color: #27AE60; font-weight: bold; }
        .status-bad { color: #E74C3C; font-weight: bold; }
        .status-warn { color: #FF8C00; font-weight: bold; }
        .status-info { color: #FF8C00; font-weight: bold; }
        
        .button-group { display: flex; gap: 10px; flex-wrap: wrap; }
        button { background: #FF8C00; color: #FFFFFF; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; transition: all 0.3s; }
        button:hover { background: #FFA500; transform: translateY(-2px); box-shadow: 0 4px 8px rgba(255,140,0,0.3); }
        button.danger { background: #E74C3C; color: #FFFFFF; }
        button.danger:hover { background: #C0392B; }
        
        .mode-toggle { padding: 15px; border-radius: 5px; text-align: center; margin-bottom: 20px; font-weight: bold; }
        .mode-toggle.exam { background: #FFEBEE; border: 2px solid #E74C3C; color: #E74C3C; }
        .mode-toggle.lab { background: #E8F5E9; border: 2px solid #27AE60; color: #27AE60; }
        
        .violation-list { max-height: 400px; overflow-y: auto; }
        .violation-item { background: #F5F5F5; padding: 10px; margin-bottom: 8px; border-left: 3px solid #FF8C00; border-radius: 3px; font-size: 13px; }
        .violation-item.blocked { border-left-color: #E74C3C; background: #FFEBEE; }
        .violation-item.allowed { border-left-color: #27AE60; background: #E8F5E9; }
        
        .stat { display: inline-block; margin-right: 20px; text-align: center; }
        .stat-value { font-size: 24px; font-weight: bold; color: #FF8C00; }
        .stat-label { font-size: 12px; color: #666666; }
        
        .test-buttons { margin-top: 15px; }
        .test-btn { background: #FFA500; margin-right: 8px; margin-bottom: 8px; font-size: 12px; padding: 8px 15px; }
        .test-btn:hover { background: #FF8C00; }
        
        .log-container { background: #F5F5F5; padding: 15px; border-radius: 5px; max-height: 300px; overflow-y: auto; font-family: monospace; font-size: 12px; border: 1px solid #FF8C00; }
        .log-line { margin-bottom: 5px; }
        .log-time { color: #999999; }
        .log-success { color: #27AE60; }
        .log-error { color: #E74C3C; }
        .log-info { color: #FF8C00; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ AURA-EDU Agent System</h1>
            <p class="subtitle">Cybersecurity with Agents - Prototype Demo</p>
        </header>
        
        <!-- Admin Warning Banner -->
        <div style="background: #FFE8D6; border: 2px solid #FF8C00; border-radius: 8px; padding: 15px; margin-bottom: 20px; color: #D84315;">
            <strong>⚠️ IMPORTANT: Administrator Privileges Required</strong><br>
            <div style="font-size: 13px; margin-top: 10px; color: #BF360C;">
                For actual domain blocking to work (hosts file modification), please:
                <br>1. Right-click your Terminal/VS Code
                <br>2. Select "Run as Administrator"
                <br>3. Run: <code style="background: #FFFFFF; padding: 2px 5px; border-radius: 3px; color: #FF8C00; border: 1px solid #FF8C00;">python demo_app.py</code>
                <br><br>Without admin rights, the demo will only show DECISIONS but NOT enforce blocks.
            </div>
        </div>
        
        <!-- Mode Toggle -->
        <div class="mode-toggle" id="modeDisplay">
            MODE: LAB (Permissive)
        </div>
        
        <!-- Main Grid -->
        <div class="grid">
            <!-- Left Column -->
            <div>
                <!-- Threat Database Stats -->
                <div class="card">
                    <h2>🗄️ Threat Database</h2>
                    <div id="threatStats" class="status-box">Loading...</div>
                </div>
                
                <!-- Controller Status -->
                <div class="card">
                    <h2>🎮 Exam Block Controller</h2>
                    <div id="controllerStats" class="status-box">Loading...</div>
                </div>
            </div>
            
            <!-- Right Column -->
            <div>
                <!-- Decision Statistics -->
                <div class="card">
                    <h2>📊 Decision Statistics</h2>
                    <div id="decisionStats" style="text-align: center; padding: 20px;">
                        <div class="stat">
                            <div class="stat-value" id="totalDecisions">0</div>
                            <div class="stat-label">Decisions</div>
                        </div>
                        <div class="stat">
                            <div class="stat-value" id="blockedCount">0</div>
                            <div class="stat-label">Blocked</div>
                        </div>
                        <div class="stat">
                            <div class="stat-value" id="allowedCount">0</div>
                            <div class="stat-label">Allowed</div>
                        </div>
                    </div>
                </div>
                
                <!-- Behavioral Analyzer -->
                <div class="card">
                    <h2>🧠 Behavioral Analyzer</h2>
                    <div id="behaviorStats" class="status-box">Waiting for violations...</div>
                </div>
            </div>
        </div>
        
        <!-- Test Controls -->
        <div class="card">
            <h2>🧪 Test Scenarios</h2>
            <div style="margin-bottom: 15px; padding: 10px; background: #FFF3E0; border-radius: 5px; color: #E65100; font-weight: bold; font-size: 13px; border-left: 3px solid #FF8C00;">
                ⚡ Auto-Test Running (3s interval) - Violations generated automatically
                <br><span style="font-size: 12px; color: #FF8C00;">Decision logic tested every 3 seconds</span>
            </div>
            <div style="margin-bottom: 15px; padding: 10px; background: #F1F8E9; border-radius: 5px; color: #33691E; font-weight: bold; font-size: 13px; border-left: 3px solid #689F38;">
                🔒 EXAM Mode Blocking:
                <br><span style="font-size: 12px; color: #558B2F;">• ChatGPT, OpenAI, Claude, Gemini (AI tools)</span>
                <br><span style="font-size: 12px; color: #558B2F;">• Facebook, Instagram, Twitter, TikTok (social media)</span>
                <br><span style="font-size: 12px; color: #558B2F;">• YouTube, Netflix, Twitch, Spotify (streaming)</span>
                <br><span style="font-size: 12px; color: #558B2F;">• USB Mass Storage devices</span>
                <br><span style="font-size: 12px; color: #558B2F;">• VPN/Tor/Proxy tools</span>
            </div>
            <div class="button-group">
                <button onclick="toggleAutoTest()">⏸️ Toggle Auto-Test</button>
                <button onclick="switchMode()">🔄 Switch Mode (LAB ↔ EXAM)</button>
                <button class="danger" onclick="testViolation('usb')">Test: USB Block</button>
                <button class="danger" onclick="testViolation('ai')">Test: AI Tool Block</button>
                <button class="danger" onclick="testViolation('vpn')">Test: VPN Block</button>
                <button class="danger" onclick="testViolation('unknown')">Test: Unknown Process</button>
                <button class="danger" onclick="testViolation('spike')">Test: Violation Spike</button>
                <button onclick="clearLogs()">Clear Logs</button>
            </div>
        </div>
        
        <!-- Real-time Log -->
        <div class="card">
            <h2>📝 Real-Time Decision Log</h2>
            <div class="log-container" id="logContainer">
                <div class="log-line log-info"><span class="log-time">[Waiting]</span> System ready. Run tests to generate logs.</div>
            </div>
        </div>
        
        <!-- Recent Violations -->
        <div class="card" style="margin-top: 20px;">
            <h2>🚨 Recent Violations & Decisions</h2>
            <div class="violation-list" id="violationList">
                <div class="status-box">No violations yet. Click test buttons above.</div>
            </div>
        </div>
    </div>
    
    <script>
        setInterval(updateDashboard, 500);
        updateDashboard();
        
        function toggleAutoTest() {
            fetch('/api/toggle_auto_test', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    addLog('Auto-test ' + (data.enabled ? 'enabled' : 'disabled'), 'info');
                    updateDashboard();
                });
        }
        
        function switchMode() {
            fetch('/api/switch_mode', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    current_mode = data.mode;
                    updateDashboard();
                    addLog('Mode switched to: ' + data.mode, 'info');
                });
        }
        
        function testViolation(type) {
            fetch('/api/test_violation', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type: type })
            })
            .then(r => r.json())
            .then(data => updateDashboard());
        }
        
        function clearLogs() {
            fetch('/api/clear_logs', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    document.getElementById('logContainer').innerHTML = '<div class="log-line log-info"><span class="log-time">[' + new Date().toLocaleTimeString() + ']</span> Logs cleared</div>';
                    updateDashboard();
                });
        }
        
        function updateDashboard() {
            fetch('/api/status')
                .then(r => r.json())
                .then(data => {
                    // Update mode
                    let modeEl = document.getElementById('modeDisplay');
                    if (data.mode === 'EXAM') {
                        modeEl.className = 'mode-toggle exam';
                        modeEl.innerHTML = '⚠️ MODE: EXAM (Strict Enforcement)';
                    } else {
                        modeEl.className = 'mode-toggle lab';
                        modeEl.innerHTML = '✓ MODE: LAB (Permissive)';
                    }
                    
                    // Update threat stats
                    let threatHtml = `<span class="status-good">✓ Database Loaded</span><br>`;
                    threatHtml += data.threat_count.blocked_domains + ` blocked domains<br>`;
                    threatHtml += data.threat_count.blocked_processes + ` blocked processes<br>`;
                    threatHtml += data.threat_count.vpn_tools + ` VPN tools<br>`;
                    threatHtml += data.threat_count.total_threats + ` total threats`;
                    document.getElementById('threatStats').innerHTML = threatHtml;
                    
                    // Update controller stats
                    let controllerHtml = `<span class="status-good">✓ Ready</span><br>`;
                    controllerHtml += `Mode: <span class="status-info">${data.mode}</span><br>`;
                    controllerHtml += `Decisions: ${data.controller_stats.total_decisions}<br>`;
                    controllerHtml += `Confidence: ${data.controller_stats.avg_confidence}`;
                    document.getElementById('controllerStats').innerHTML = controllerHtml;
                    
                    // Update decision stats
                    document.getElementById('totalDecisions').innerHTML = data.controller_stats.total_decisions;
                    document.getElementById('blockedCount').innerHTML = data.controller_stats.blocked;
                    document.getElementById('allowedCount').innerHTML = data.controller_stats.allowed;
                    
                    // Update behavior stats
                    let behaviorHtml = `<span class="status-info">Risk Score: ${data.behavior_stats.risk_score}</span><br>`;
                    behaviorHtml += `Risk Level: <span class="status-${getRiskColor(data.behavior_stats.risk_level)}">${data.behavior_stats.risk_level}</span><br>`;
                    behaviorHtml += `Factors: ${data.behavior_stats.factors.length || 0}<br>`;
                    if (data.behavior_stats.needs_gemini) {
                        behaviorHtml += `<span class="status-warn">⚠ Gemini call needed (ambiguous)</span>`;
                    }
                    document.getElementById('behaviorStats').innerHTML = behaviorHtml;
                    
                    // Update log with better formatting
                    let logHtml = '';
                    if (!data.logs || data.logs.length === 0) {
                        logHtml = '<div class="log-line log-info">No decisions yet. Run tests to generate logs.</div>';
                    } else {
                        data.logs.forEach(log => {
                            let color = 'info';
                            if (log.includes('BLOCK')) color = 'error';
                            if (log.includes('ALLOW')) color = 'success';
                            logHtml += `<div class="log-line log-${color}">${log}</div>`;
                        });
                    }
                    let logContainer = document.getElementById('logContainer');
                    logContainer.innerHTML = logHtml;
                    // Auto-scroll to bottom
                    logContainer.scrollTop = logContainer.scrollHeight;
                    
                    // Update violations with better formatting
                    let violationHtml = '';
                    if (!data.recent_violations || data.recent_violations.length === 0) {
                        violationHtml = '<div class="status-box">No violations yet. Click test buttons above.</div>';
                    } else {
                        data.recent_violations.forEach(v => {
                            let className = v.allowed ? 'allowed' : 'blocked';
                            let icon = v.allowed ? 'ALLOW' : 'BLOCK';
                            let timestamp = v.timestamp ? v.timestamp.split('T')[1].substring(0, 8) : '';
                            violationHtml += `<div class="violation-item ${className}">
                                <strong>[${icon}] ${v.reason}</strong> <span style="color: #999999">${timestamp}</span><br>
                                Confidence: ${v.confidence}% | Source: ${v.source} | Mode: ${v.mode}
                            </div>`;
                        });
                    }
                    document.getElementById('violationList').innerHTML = violationHtml;
                });
        }
        
        function addLog(msg, type = 'info') {
            let logContainer = document.getElementById('logContainer');
            let time = new Date().toLocaleTimeString();
            let logHtml = `<div class="log-line log-${type}"><span class="log-time">[${time}]</span> ${msg}</div>`;
            logContainer.innerHTML += logHtml;
            logContainer.scrollTop = logContainer.scrollHeight;
        }
        
        function getRiskColor(level) {
            if (level === 'critical' || level === 'high') return 'error';
            if (level === 'medium') return 'warn';
            return 'success';
        }
    </script>
</body>
</html>
'''


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/status')
def api_status():
    """Get current system status"""
    global current_mode, controller
    threat_counts = threat_db.get_threat_count()
    
    # Ensure controller mode is synced with current_mode
    controller.mode = current_mode
    controller_stats = controller.get_statistics()
    
    device_id = "demo_device_001"
    behavior_summary = analyzer.get_device_summary(device_id)
    risk_analysis = behavior_summary["risk_analysis"]
    
    # Debug: Print what's in decision log
    print(f"\n[API] Current mode: {current_mode} (controller: {controller.mode})")
    print(f"[API] Decision log size: {len(controller.decision_log)}")
    if controller.decision_log:
        print(f"[API] Last decision: {controller.decision_log[-1]}")
    
    # Format logs with proper timestamps
    formatted_logs = []
    for log in controller.decision_log[-20:]:
        try:
            timestamp = log.get('timestamp', '')
            if timestamp:
                # Parse ISO timestamp and format it
                time_str = timestamp.split('T')[1][:8] if 'T' in timestamp else datetime.now().strftime('%H:%M:%S')
            else:
                time_str = datetime.now().strftime('%H:%M:%S')
            
            action_str = log.get('action', 'block').upper()
            reason = log.get('reason', 'Unknown')
            confidence = log.get('confidence', 0)
            
            log_line = f"[{time_str}] {reason} - {action_str} ({confidence}% confidence)"
            formatted_logs.append(log_line)
        except Exception as e:
            formatted_logs.append(f"Error formatting log: {e}")
    
    # Format violations for dashboard
    recent_violations = []
    for log in controller.decision_log[-10:]:
        try:
            violation = {
                "reason": log.get("reason", "Unknown"),
                "allowed": log.get("allowed", False),
                "confidence": log.get("confidence", 0),
                "mode": log.get("mode", current_mode),
                "source": log.get("source", "unknown"),
                "action": log.get("action", "block"),
                "timestamp": log.get("timestamp", "")
            }
            recent_violations.append(violation)
        except Exception as e:
            print(f"[API-ERROR] Error formatting violation: {e}")
    
    return jsonify({
        "mode": current_mode,
        "threat_count": threat_counts,
        "controller_stats": controller_stats,
        "behavior_stats": {
            "risk_score": int(risk_analysis["risk_score"]),
            "risk_level": risk_analysis["risk_level"],
            "factors": risk_analysis["factors"],
            "needs_gemini": behavior_summary["gemini_decision"]["call_gemini"]
        },
        "logs": formatted_logs,
        "recent_violations": recent_violations
    })


@app.route('/api/switch_mode', methods=['POST'])
def api_switch_mode():
    """Switch between LAB and EXAM modes"""
    global current_mode, controller, web_filter
    current_mode = "EXAM" if current_mode == "LAB" else "LAB"
    
    # Update controller mode (don't reinitialize - preserves decision log)
    controller.mode = current_mode
    
    # Apply or remove web blocking based on mode
    response_data = {
        "mode": current_mode,
        "status": "switched",
        "blocking": current_mode == "EXAM"
    }
    
    try:
        if current_mode == "EXAM":
            print("[API] EXAM MODE: Applying web blocking...")
            web_filter.apply_blocking(mode="EXAM")
            print("[API] Web blocking applied successfully")
            response_data["blocking_status"] = "applied"
        else:
            print("[API] LAB MODE: Removing web blocking...")
            web_filter.remove_blocking()
            print("[API] Web blocking removed successfully")
            response_data["blocking_status"] = "removed"
    
    except PermissionError:
        print("[API] ERROR: Administrator privileges required!")
        print("[API] Please run Terminal/VS Code as Administrator")
        response_data["error"] = "ADMIN_REQUIRED"
        response_data["error_message"] = "Administrator privileges required. Right-click VS Code/Terminal and select 'Run as Administrator'"
        return jsonify(response_data), 403
    
    except Exception as e:
        print(f"[API] Error applying/removing blocking: {e}")
        response_data["error"] = "BLOCKING_ERROR"
        response_data["error_message"] = str(e)
        return jsonify(response_data), 500
    
    analyzer.clear_history()
    return jsonify(response_data)


@app.route('/api/test_violation', methods=['POST'])
def api_test_violation():
    """Test a violation scenario"""
    global controller, current_mode
    data = request.json
    violation_type = data.get("type", "unknown")
    device_id = "demo_device_001"
    now = datetime.now()
    
    # Ensure controller mode is synced with current_mode
    controller.mode = current_mode
    
    test_cases = {
        "usb": {
            "scenario": "USB Mass Storage Insertion",
            "domain": None,
            "process": None,
            "usb_device": "SanDisk_Flash_Drive",
            "decision_func": lambda: controller.check_usb_device("SanDisk_Flash_Drive", "mass_storage")
        },
        "ai": {
            "scenario": "ChatGPT Web Access",
            "domain": "chat.openai.com",
            "process": None,
            "decision_func": lambda: controller.check_domain_access("chat.openai.com")
        },
        "vpn": {
            "scenario": "Tor.exe Process Startup",
            "domain": None,
            "process": "tor.exe",
            "decision_func": lambda: controller.check_process_execution("tor.exe", "C:\\AppData\\Tor\\tor.exe")
        },
        "unknown": {
            "scenario": "Unknown Executable",
            "domain": None,
            "process": "suspicious.exe",
            "decision_func": lambda: controller.check_process_execution("suspicious.exe", "C:\\Users\\Desktop\\suspicious.exe")
        },
        "spike": {
            "scenario": "Violation Spike (5 violations)",
            "process": "spike_test",
            "decision_func": None
        }
    }
    
    if violation_type not in test_cases:
        return jsonify({"error": "Unknown test type"}), 400
    
    test_case = test_cases[violation_type]
    
    if violation_type == "spike":
        # Generate spike - multiple violations in succession
        for i in range(5):
            analyzer.log_violation(device_id, f"spike_test_{i}", {"index": i}, confidence=70)
        log_msg = f"[TEST-SPIKE] Generated 5 violations in succession | Mode: {controller.mode}"
        print(log_msg)
        # Log to agent logger
        logger.log_event("TEST_SPIKE", {
            "count": 5,
            "reason": "Multiple violations detected",
            "mode": controller.mode
        })
    else:
        # Single violation test
        decision = test_case["decision_func"]()
        print(f"[TEST-{violation_type.upper()}] {test_case['scenario']} | Mode: {controller.mode} | Allowed: {decision['allowed']} | Reason: {decision['reason']} | Confidence: {decision['confidence']}%")
        analyzer.log_violation(
            device_id,
            test_case["scenario"],
            {"type": violation_type},
            confidence=decision["confidence"]
        )
        # Log to agent logger
        logger.log_event(f"TEST_{violation_type.upper()}", {
            "scenario": test_case["scenario"],
            "allowed": decision["allowed"],
            "reason": decision["reason"],
            "confidence": decision["confidence"],
            "source": decision["source"],
            "mode": controller.mode
        })
    
    return jsonify({
        "status": "tested", 
        "type": violation_type,
        "mode": controller.mode,
        "log_entries": len(controller.decision_log)
    })


@app.route('/api/clear_logs', methods=['POST'])
def api_clear_logs():
    """Clear all logs"""
    global controller
    controller.clear_logs()
    analyzer.clear_history()
    return jsonify({"status": "cleared"})


@app.route('/api/toggle_auto_test', methods=['POST'])
def api_toggle_auto_test():
    """Toggle auto-test generation"""
    global auto_test_enabled
    auto_test_enabled = not auto_test_enabled
    print(f"[API] Auto-test {'enabled' if auto_test_enabled else 'disabled'}")
    return jsonify({"status": "toggled", "enabled": auto_test_enabled})



if __name__ == '__main__':
    print("=" * 60)
    print("[SHIELD] AURA-EDU Agent Demo Starting")
    print("=" * 60)
    print()
    print("[OK] Threat Intelligence Database: Loaded")
    print("[OK] Exam Block Controller: Ready")
    print("[OK] Behavioral Analyzer: Ready")
    print("[OK] Web Filter: Ready (hosts file blocking)")
    print()
    print("[WARNING] Run as Administrator for web blocking to work!")
    print("[INFO] In EXAM mode, will block: ChatGPT, AI tools, social media, streaming")
    print()
    
    # Start auto-test scheduler
    scheduler.start()
    print("[AUTO-TEST] Background violation generator started")
    print()
    print("[BROWSER] Open your browser: http://localhost:5000")
    print()
    print("=" * 60)
    
    app.run(debug=True, port=5000, use_reloader=False)
