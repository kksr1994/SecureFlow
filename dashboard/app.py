#!/usr/bin/env python3
from flask import Flask, render_template, jsonify, request
import json, os, subprocess, threading, re
from pathlib import Path
from datetime import datetime

app = Flask(__name__)
SCAN_DIR = Path(__file__).parent.parent / 'data' / 'scans'
PROJECT_ROOT = Path(__file__).parent.parent

scan_status = {'running': False, 'progress': '', 'last_scan': None}

def clean_ansi(text):
    """Remove ANSI color codes from text"""
    return re.sub(r'\x1b\[[0-9;]*m', '', str(text))

def get_latest_unified_report():
    try:
        reports = sorted(SCAN_DIR.glob('unified_report_*.json'), reverse=True)
        if reports:
            with open(reports[0]) as f:
                return json.load(f)
    except Exception as e:
        print(f"Error: {e}")
    return None

def get_semgrep_findings():
    try:
        files = sorted(SCAN_DIR.glob('semgrep_scan_*.json'), reverse=True)
        if not files:
            return []
        with open(files[0]) as f:
            data = json.load(f)
        findings = []
        for r in data.get('results', []):
            findings.append({
                'rule_id': r.get('check_id', 'Unknown'),
                'file': r.get('path', 'Unknown'),
                'line': r.get('start', {}).get('line', 0),
                'message': r.get('extra', {}).get('message', 'No message'),
                'severity': r.get('extra', {}).get('severity', 'WARNING'),
                'category': r.get('extra', {}).get('metadata', {}).get('category', 'security'),
                'cwe': r.get('extra', {}).get('metadata', {}).get('cwe', []),
                'owasp': r.get('extra', {}).get('metadata', {}).get('owasp', []),
            })
        return findings
    except Exception as e:
        print(f"Semgrep error: {e}")
        return []

def get_trivy_findings():
    try:
        files = sorted(SCAN_DIR.glob('trivy_scan_*.json'), reverse=True)
        if not files:
            return []
        with open(files[0]) as f:
            data = json.load(f)
        findings = []
        for result in data.get('Results', []):
            for v in result.get('Vulnerabilities', []):
                findings.append({
                    'cve_id': v.get('VulnerabilityID', 'N/A'),
                    'package': v.get('PkgName', 'Unknown'),
                    'installed_version': v.get('InstalledVersion', 'N/A'),
                    'fixed_version': v.get('FixedVersion', 'N/A'),
                    'severity': v.get('Severity', 'UNKNOWN'),
                    'title': v.get('Title', 'No title'),
                    'description': v.get('Description', '')[:200],
                    'url': v.get('PrimaryURL', ''),
                })
        return findings
    except Exception as e:
        print(f"Trivy error: {e}")
        return []

def get_trufflehog_findings():
    try:
        files = sorted(SCAN_DIR.glob('trufflehog_scan_*.json'), reverse=True)
        if not files:
            return []
        with open(files[0]) as f:
            data = json.load(f)
        findings = []
        if isinstance(data, list):
            for item in data:
                # Clean ANSI codes from keys and values
                clean = {}
                for k, v in item.items():
                    clean_key = clean_ansi(k)
                    clean_val = clean_ansi(v) if isinstance(v, str) else v
                    clean[clean_key] = clean_val
                findings.append({
                    'reason': clean.get('Reason', 'Unknown'),
                    'filepath': clean.get('Filepath', 'Unknown'),
                    'date': clean.get('Date', 'Unknown'),
                    'branch': clean.get('Branch', 'Unknown'),
                    'commit': clean.get('Commit', 'Unknown'),
                })
        return findings
    except Exception as e:
        print(f"TruffleHog error: {e}")
        return []

def run_scan_background(target_path, scanners):
    global scan_status
    scan_status['running'] = True
    scan_status['progress'] = f'Scanning {target_path}...'
    try:
        cmd = ['python3', str(PROJECT_ROOT / 'cli' / 'main.py'), 'scan', '-t', str(target_path), '-s', scanners]
        print(f"Running: {' '.join(cmd)}")
        subprocess.run(cmd, capture_output=True, text=True, cwd=str(PROJECT_ROOT))
        scan_status['progress'] = 'Scan complete!'
        scan_status['last_scan'] = datetime.now().isoformat()
    except Exception as e:
        scan_status['progress'] = f'Error: {str(e)}'
    finally:
        scan_status['running'] = False

@app.route('/')
def index():
    report = get_latest_unified_report()
    return render_template('dashboard.html', report=report,
                         scan_status=scan_status,
                         scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

@app.route('/results')
def results():
    report = get_latest_unified_report()
    semgrep = get_semgrep_findings()
    trivy = get_trivy_findings()
    trufflehog = get_trufflehog_findings()
    return render_template('results.html',
                         report=report,
                         semgrep=semgrep,
                         trivy=trivy,
                         trufflehog=trufflehog,
                         scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

@app.route('/api/browse')
def api_browse():
    current = request.args.get('path', str(Path.home()))
    try:
        current_path = Path(current)
        if not current_path.exists():
            current_path = Path.home()
        dirs = []
        for item in sorted(current_path.iterdir()):
            if item.is_dir() and not item.name.startswith('.'):
                dirs.append({'name': item.name, 'path': str(item)})
        return jsonify({'current': str(current_path), 'parent': str(current_path.parent), 'dirs': dirs})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    target = data.get('target', '').strip()
    scanners = data.get('scanners', 'all')
    if target.startswith('~'):
        target_path = Path(os.path.expanduser(target))
    elif os.path.isabs(target):
        target_path = Path(target)
    else:
        target_path = PROJECT_ROOT / target
    if not target_path.exists():
        return jsonify({'error': f'Path not found: {target_path}'}), 400
    if scan_status['running']:
        return jsonify({'error': 'Scan already running!'}), 400
    thread = threading.Thread(target=run_scan_background, args=(target_path, scanners))
    thread.daemon = True
    thread.start()
    return jsonify({'status': 'started', 'message': f'Scanning: {target_path}', 'target': str(target_path)})

@app.route('/api/status')
def api_status():
    return jsonify(scan_status)

if __name__ == '__main__':
    print("🚀 Starting SecureFlow Dashboard...")
    print("📊 Dashboard: http://localhost:5000")
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
