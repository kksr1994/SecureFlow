#!/usr/bin/env python3
"""
Semgrep Scanner Module
This module runs Semgrep and parses its results
"""

import subprocess
import json
import os
from datetime import datetime
from pathlib import Path


class SemgrepScanner:
    """Class to handle Semgrep scanning operations"""
    
    def __init__(self, target_path, output_dir="data/scans"):
        """
        Initialize the scanner
        
        Args:
            target_path: Path to scan (file or directory)
            output_dir: Where to save results
        """
        self.target_path = target_path
        self.output_dir = output_dir
        self.results = None
        
        # Create output directory if it doesn't exist
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    def run_scan(self):
        """
        Run Semgrep scan on target path
        
        Returns:
            dict: Parsed scan results
        """
        print(f"🔍 Running Semgrep scan on: {self.target_path}")
        
        try:
            # Build the command
            command = [
                'semgrep',
                '--config=auto',  # Use automatic rules
                '--json',         # Output as JSON
                self.target_path
            ]
            
            # Run the command
            result = subprocess.run(
                command,
                capture_output=True,  # Capture stdout and stderr
                text=True,            # Return string, not bytes
                check=False           # Don't raise exception on non-zero exit
            )
            
            # Parse JSON output
            if result.stdout:
                self.results = json.loads(result.stdout)
                findings_count = len(self.results.get('results', []))
                print(f"✓ Scan completed! Found {findings_count} findings")
                return self.results
            else:
                print("⚠ No output from Semgrep")
                return None
                
        except Exception as e:
            print(f"✗ Error running Semgrep: {e}")
            return None
    
    def save_results(self, filename=None):
        """
        Save scan results to JSON file
        
        Args:
            filename: Custom filename (optional)
        """
        if not self.results:
            print("⚠ No results to save")
            return None
        
        # Generate filename with timestamp
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"semgrep_scan_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Write to file
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"💾 Results saved to: {filepath}")
        return filepath
    
    def get_summary(self):
        """
        Get a summary of findings
        
        Returns:
            dict: Summary statistics
        """
        if not self.results:
            return None
        
        findings = self.results.get('results', [])
        
        # Count by severity
        severity_count = {
            'ERROR': 0,
            'WARNING': 0,
            'INFO': 0
        }
        
        # Count by category
        category_count = {}
        
        for finding in findings:
            # Get severity
            severity = finding.get('extra', {}).get('severity', 'INFO')
            severity_count[severity] = severity_count.get(severity, 0) + 1
            
            # Get category from rule ID
            rule_id = finding.get('check_id', '')
            if 'sql-injection' in rule_id or 'sql' in rule_id.lower():
                category = 'SQL Injection'
            elif 'xss' in rule_id or 'cross-site' in rule_id:
                category = 'XSS'
            elif 'command-injection' in rule_id or 'system-call' in rule_id:
                category = 'Command Injection'
            elif 'secrets' in rule_id or 'api-key' in rule_id:
                category = 'Secrets'
            elif 'eval' in rule_id:
                category = 'Code Injection'
            elif 'path-traversal' in rule_id:
                category = 'Path Traversal'
            elif 'debug' in rule_id or 'md5' in rule_id:
                category = 'Security Misconfiguration'
            else:
                category = 'Other'
            
            category_count[category] = category_count.get(category, 0) + 1
        
        summary = {
            'total_findings': len(findings),
            'by_severity': severity_count,
            'by_category': category_count,
            'scanned_path': self.target_path,
            'scan_time': datetime.now().isoformat()
        }
        
        return summary
    
    def print_findings(self, max_findings=10):
        """
        Print findings in a readable format
        
        Args:
            max_findings: Maximum number of findings to display
        """
        if not self.results:
            print("⚠ No results to display")
            return
        
        findings = self.results.get('results', [])
        
        if not findings:
            print("✓ No vulnerabilities found!")
            return
        
        print("\n" + "="*80)
        print(f"📊 SEMGREP SCAN RESULTS")
        print("="*80)
        
        # Print summary
        summary = self.get_summary()
        print(f"\n📈 Summary:")
        print(f"   Total Findings: {summary['total_findings']}")
        print(f"   🔴 ERROR:   {summary['by_severity'].get('ERROR', 0)}")
        print(f"   🟡 WARNING: {summary['by_severity'].get('WARNING', 0)}")
        print(f"   🔵 INFO:    {summary['by_severity'].get('INFO', 0)}")
        
        print(f"\n📂 By Category:")
        for category, count in sorted(summary['by_category'].items(), key=lambda x: x[1], reverse=True):
            print(f"   {category}: {count}")
        
        print(f"\n🔍 Detailed Findings (showing {min(max_findings, len(findings))} of {len(findings)}):\n")
        
        # Print individual findings
        for idx, finding in enumerate(findings[:max_findings], 1):
            severity = finding.get('extra', {}).get('severity', 'INFO')
            message = finding.get('extra', {}).get('message', 'No message')
            path = finding.get('path', 'Unknown file')
            line = finding.get('start', {}).get('line', '?')
            rule_id = finding.get('check_id', 'Unknown rule')
            
            # Color code by severity
            severity_icon = {
                'ERROR': '🔴',
                'WARNING': '🟡',
                'INFO': '🔵'
            }.get(severity, '⚪')
            
            print(f"{severity_icon} [{severity}] Finding #{idx}")
            print(f"   Rule: {rule_id}")
            print(f"   File: {path}:{line}")
            print(f"   Issue: {message[:120]}...")
            print()
        
        if len(findings) > max_findings:
            print(f"   ... and {len(findings) - max_findings} more findings")
            print(f"   💡 Tip: Use --all flag to see all findings\n")
    
    def get_critical_findings(self):
        """Get only ERROR severity findings"""
        if not self.results:
            return []
        
        findings = self.results.get('results', [])
        critical = [
            f for f in findings 
            if f.get('extra', {}).get('severity') == 'ERROR'
        ]
        
        return critical


# Example usage (for testing this module directly)
if __name__ == "__main__":
    # Test the scanner
    scanner = SemgrepScanner("test-apps/vulnerable-app")
    scanner.run_scan()
    scanner.print_findings(max_findings=30)  # Show all findings
    scanner.save_results()
    
    # Print summary
    summary = scanner.get_summary()
    print(f"\n📊 Final Summary:")
    print(json.dumps(summary, indent=2))
