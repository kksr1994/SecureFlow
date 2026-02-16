#!/usr/bin/env python3
"""
SecureFlow - Security Scanner Orchestrator
"""

import sys
import os
import argparse
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import our scanners
from scanners.semgrep_scanner import SemgrepScanner
from scanners.trivy_scanner import TrivyScanner
from scanners.trufflehog_scanner import TruffleHogScanner

# ANSI colors
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    banner = f"""
{Colors.OKBLUE}{Colors.BOLD}
╔═══════════════════════════════════════════════════════╗
║                                                       ║
║              🔒 SECUREFLOW v2.0 🔒                   ║
║                                                       ║
║     Your DevSecOps Security Scanner Orchestrator     ║
║              Now with 3 Integrated Scanners!         ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝
{Colors.ENDC}
    """
    print(banner)

def print_success(message):
    print(f"{Colors.OKGREEN}✓ {message}{Colors.ENDC}")

def print_error(message):
    print(f"{Colors.FAIL}✗ {message}{Colors.ENDC}")

def print_info(message):
    print(f"{Colors.OKBLUE}ℹ {message}{Colors.ENDC}")

def print_warning(message):
    print(f"{Colors.WARNING}⚠ {message}{Colors.ENDC}")

def check_tools():
    print_info("Checking if security tools are installed...")
    
    tools = {
        'semgrep': 'semgrep --version',
        'trivy': 'trivy --version',
        'grype': 'grype version',
        'trufflehog': 'trufflehog --help'
    }
    
    all_installed = True
    
    for tool_name, command in tools.items():
        try:
            os.system(f"{command} > /dev/null 2>&1")
            print_success(f"{tool_name} is installed")
        except:
            print_error(f"{tool_name} is NOT installed")
            all_installed = False
    
    return all_installed

def scan_with_semgrep(target_path, show_all=False):
    """Run Semgrep scan on target"""
    print("\n" + "="*80)
    print_info("Starting Semgrep SAST scan...")
    print("="*80 + "\n")
    
    scanner = SemgrepScanner(target_path)
    results = scanner.run_scan()
    
    if results:
        max_findings = 100 if show_all else 20
        scanner.print_findings(max_findings=max_findings)
        
        filepath = scanner.save_results()
        
        critical = scanner.get_critical_findings()
        if critical:
            print_warning(f"\n⚠️  {len(critical)} CRITICAL (ERROR) findings!")
        
        print("\n" + "="*80)
        print_success("Semgrep scan completed!")
        print_info(f"Full results: {filepath}")
        print("="*80 + "\n")
        
        return True
    else:
        print_error("Semgrep scan failed!")
        return False

def scan_with_trivy(target_path, show_all=False):
    """Run Trivy scan on target"""
    print("\n" + "="*80)
    print_info("Starting Trivy dependency scan...")
    print("="*80 + "\n")
    
    scanner = TrivyScanner(target_path)
    results = scanner.run_scan()
    
    if results:
        max_findings = 100 if show_all else 20
        scanner.print_findings(max_findings=max_findings)
        
        filepath = scanner.save_results()
        
        summary = scanner.get_summary()
        critical_high = summary['by_severity'].get('CRITICAL', 0) + summary['by_severity'].get('HIGH', 0)
        if critical_high > 0:
            print_warning(f"\n⚠️  {critical_high} CRITICAL/HIGH vulnerabilities in dependencies!")
        
        print("\n" + "="*80)
        print_success("Trivy scan completed!")
        print_info(f"Full results: {filepath}")
        print("="*80 + "\n")
        
        return True
    else:
        print_info("Trivy scan completed - no vulnerabilities found!")
        print("\n")
        return True

def scan_with_trufflehog(target_path, show_all=False):
    """Run TruffleHog scan on target"""
    print("\n" + "="*80)
    print_info("Starting TruffleHog secret scan...")
    print("="*80 + "\n")
    
    scanner = TruffleHogScanner(target_path)
    results = scanner.run_scan()
    
    if results and len(results) > 0:
        max_findings = 100 if show_all else 20
        scanner.print_findings(max_findings=max_findings)
        
        filepath = scanner.save_results()
        
        print("\n" + "="*80)
        print_success("TruffleHog scan completed!")
        print_info(f"Full results: {filepath}")
        print("="*80 + "\n")
        
        return True
    else:
        print_info("TruffleHog scan completed - no secrets found!")
        print("\n")
        return True

def main():
    parser = argparse.ArgumentParser(
        description='SecureFlow - DevSecOps Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s check                          # Check tools
  %(prog)s scan -t test-apps/             # Scan with Semgrep
  %(prog)s scan -t . -s all               # Run ALL scanners
  %(prog)s scan -t . -s trivy             # Just dependency scan
  %(prog)s scan -t . -s all --all         # All scanners, all results
        """
    )
    
    parser.add_argument(
        'command',
        choices=['check', 'scan'],
        help='check or scan'
    )
    
    parser.add_argument(
        '-t', '--target',
        help='Target path to scan',
        default='.'
    )
    
    parser.add_argument(
        '-s', '--scanner',
        choices=['semgrep', 'trivy', 'trufflehog', 'all'],
        default='semgrep',
        help='Which scanner to use (default: semgrep)'
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='Show all findings (not just first 20)'
    )
    
    args = parser.parse_args()
    
    print_banner()
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print_info(f"Started at: {current_time}\n")
    
    if args.command == 'check':
        if check_tools():
            print("\n")
            print_success("All tools ready!")
            print_info("SecureFlow v2.0 is ready to scan!")
        else:
            print("\n")
            print_error("Some tools missing.")
            sys.exit(1)
    
    elif args.command == 'scan':
        print_info("Verifying tools...\n")
        if not check_tools():
            print_error("\nTools missing. Run 'check' first.")
            sys.exit(1)
        
        if not os.path.exists(args.target):
            print_error(f"Target not found: {args.target}")
            sys.exit(1)
        
        print_success("All tools ready!\n")
        
        # Run scan based on scanner choice
        if args.scanner == 'semgrep' or args.scanner == 'all':
            scan_with_semgrep(args.target, show_all=args.all)
        
        if args.scanner == 'trivy' or args.scanner == 'all':
            scan_with_trivy(args.target, show_all=args.all)
        
        if args.scanner == 'trufflehog' or args.scanner == 'all':
            scan_with_trufflehog(args.target, show_all=args.all)
        
        if args.scanner == 'all':
            print("\n" + "="*80)
            print_success("🎉 ALL SCANS COMPLETED!")
            print_info("Check data/scans/ for detailed JSON results")
            print_info("Summary: Semgrep (code) + Trivy (deps) + TruffleHog (secrets)")
            print("="*80 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        print_info("Cancelled by user")
        sys.exit(0)
    except Exception as e:
        print("\n")
        print_error(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
