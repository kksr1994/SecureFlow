#!/usr/bin/env python3
"""
Trivy Scanner Module
Scans for vulnerabilities in dependencies and containers
"""

import subprocess
import json
import os
from datetime import datetime
from pathlib import Path


class TrivyScanner:
    """Class to handle Trivy scanning operations"""
    
    def __init__(self, target_path, output_dir="data/scans"):
        """
        Initialize the scanner
        
        Args:
            target_path: Path to scan (directory or file)
            output_dir: Where to save results
        """
        self.target_path = target_path
        self.output_dir = output_dir
        self.results = None
        
        # Create output directory if it doesn't exist
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    def run_scan(self, scan_type="fs"):
        """
        Run Trivy scan
        
        Args:
            scan_type: Type of scan (fs=filesystem, image=container)
        
        Returns:
            dict: Parsed scan results
        """
        print(f"🔍 Running Trivy scan on: {self.target_path}")
        
        try:
            # Build the command
            command = [
                'trivy',
                scan_type,
                '--format', 'json',
                '--scanners', 'vuln',
                self.target_path
            ]
            
            # Run the command
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False
            )
            
            # Parse JSON output
            if result.stdout:
                self.results = json.loads(result.stdout)
                
                # Count total vulnerabilities
                total_vulns = 0
                if 'Results' in self.results:
                    for res in self.results['Results']:
                        if 'Vulnerabilities' in res and res['Vulnerabilities']:
                            total_vulns += len(res['Vulnerabilities'])
                
                print(f"✓ Scan completed! Found {total_vulns} vulnerabilities")
                return self.results
            else:
                print("⚠ No output from Trivy")
                return None
                
        except Exception as e:
            print(f"✗ Error running Trivy: {e}")
            return None
    
    def save_results(self, filename=None):
        """Save scan results to JSON file"""
        if not self.results:
            print("⚠ No results to save")
            return None
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"trivy_scan_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"💾 Results saved to: {filepath}")
        return filepath
    
    def get_summary(self):
        """Get summary of findings"""
        if not self.results:
            return None
        
        severity_count = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'UNKNOWN': 0
        }
        
        vulnerabilities = []
        
        if 'Results' in self.results:
            for result in self.results['Results']:
                if 'Vulnerabilities' in result and result['Vulnerabilities']:
                    for vuln in result['Vulnerabilities']:
                        severity = vuln.get('Severity', 'UNKNOWN')
                        severity_count[severity] = severity_count.get(severity, 0) + 1
                        vulnerabilities.append(vuln)
        
        summary = {
            'total_vulnerabilities': len(vulnerabilities),
            'by_severity': severity_count,
            'scanned_path': self.target_path,
            'scan_time': datetime.now().isoformat()
        }
        
        return summary
    
    def print_findings(self, max_findings=10):
        """Print findings in readable format"""
        if not self.results:
            print("⚠ No results to display")
            return
        
        print("\n" + "="*80)
        print(f"📊 TRIVY SCAN RESULTS")
        print("="*80)
        
        summary = self.get_summary()
        print(f"\n📈 Summary:")
        print(f"   Total Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"   🔴 CRITICAL: {summary['by_severity'].get('CRITICAL', 0)}")
        print(f"   🟠 HIGH:     {summary['by_severity'].get('HIGH', 0)}")
        print(f"   🟡 MEDIUM:   {summary['by_severity'].get('MEDIUM', 0)}")
        print(f"   🟢 LOW:      {summary['by_severity'].get('LOW', 0)}")
        
        if summary['total_vulnerabilities'] == 0:
            print("\n✓ No vulnerabilities found!")
            return
        
        print(f"\n🔍 Detailed Findings (showing {min(max_findings, summary['total_vulnerabilities'])} of {summary['total_vulnerabilities']}):\n")
        
        count = 0
        if 'Results' in self.results:
            for result in self.results['Results']:
                if 'Vulnerabilities' in result and result['Vulnerabilities']:
                    target = result.get('Target', 'Unknown')
                    
                    for vuln in result['Vulnerabilities'][:max_findings - count]:
                        count += 1
                        severity = vuln.get('Severity', 'UNKNOWN')
                        vuln_id = vuln.get('VulnerabilityID', 'Unknown')
                        pkg_name = vuln.get('PkgName', 'Unknown')
                        installed = vuln.get('InstalledVersion', 'Unknown')
                        fixed = vuln.get('FixedVersion', 'Not available')
                        title = vuln.get('Title', 'No description')
                        
                        severity_icon = {
                            'CRITICAL': '🔴',
                            'HIGH': '🟠',
                            'MEDIUM': '🟡',
                            'LOW': '🟢',
                            'UNKNOWN': '⚪'
                        }.get(severity, '⚪')
                        
                        print(f"{severity_icon} [{severity}] Finding #{count}")
                        print(f"   CVE: {vuln_id}")
                        print(f"   Package: {pkg_name} ({installed})")
                        print(f"   Fixed in: {fixed}")
                        print(f"   Issue: {title[:100]}...")
                        print()
                        
                        if count >= max_findings:
                            break
                
                if count >= max_findings:
                    break
        
        if summary['total_vulnerabilities'] > max_findings:
            print(f"   ... and {summary['total_vulnerabilities'] - max_findings} more vulnerabilities")
            print(f"   💡 Tip: Use --all flag to see all findings\n")


# Example usage
if __name__ == "__main__":
    scanner = TrivyScanner("test-apps/vulnerable-app")
    scanner.run_scan()
    scanner.print_findings(max_findings=30)
    scanner.save_results()
    
    summary = scanner.get_summary()
    print(f"\n📊 Final Summary:")
    print(json.dumps(summary, indent=2))
