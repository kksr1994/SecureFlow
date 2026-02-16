#!/usr/bin/env python3
"""
Result Aggregator
Combines results from multiple scanners into unified report
"""

import json
import os
from datetime import datetime
from pathlib import Path


class ResultAggregator:
    """Aggregates results from multiple security scanners"""
    
    def __init__(self, scan_dir="data/scans"):
        """Initialize aggregator"""
        self.scan_dir = scan_dir
        self.semgrep_results = None
        self.trivy_results = None
        self.trufflehog_results = None
        
    def load_latest_results(self):
        """Load the most recent scan results from each scanner"""
        scan_path = Path(self.scan_dir)
        
        # Find latest Semgrep scan
        semgrep_files = sorted(scan_path.glob("semgrep_scan_*.json"), reverse=True)
        if semgrep_files:
            with open(semgrep_files[0], 'r') as f:
                self.semgrep_results = json.load(f)
        
        # Find latest Trivy scan
        trivy_files = sorted(scan_path.glob("trivy_scan_*.json"), reverse=True)
        if trivy_files:
            with open(trivy_files[0], 'r') as f:
                self.trivy_results = json.load(f)
        
        # Find latest TruffleHog scan
        trufflehog_files = sorted(scan_path.glob("trufflehog_scan_*.json"), reverse=True)
        if trufflehog_files:
            with open(trufflehog_files[0], 'r') as f:
                self.trufflehog_results = json.load(f)
    
    def get_unified_summary(self):
        """Create unified summary from all scanners"""
        summary = {
            'scan_time': datetime.now().isoformat(),
            'scanners_used': [],
            'total_findings': 0,
            'by_scanner': {},
            'by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            },
            'by_category': {}
        }
        
        # Semgrep results
        if self.semgrep_results:
            semgrep_count = len(self.semgrep_results.get('results', []))
            summary['scanners_used'].append('Semgrep')
            summary['by_scanner']['Semgrep'] = {
                'findings': semgrep_count,
                'type': 'SAST (Code Analysis)'
            }
            summary['total_findings'] += semgrep_count
            
            # Count by severity (Semgrep uses ERROR/WARNING)
            for finding in self.semgrep_results.get('results', []):
                severity = finding.get('extra', {}).get('severity', 'MEDIUM')
                if severity == 'ERROR':
                    summary['by_severity']['CRITICAL'] += 1
                elif severity == 'WARNING':
                    summary['by_severity']['MEDIUM'] += 1
        
        # Trivy results
        if self.trivy_results:
            trivy_count = 0
            if 'Results' in self.trivy_results:
                for result in self.trivy_results['Results']:
                    if 'Vulnerabilities' in result and result['Vulnerabilities']:
                        trivy_count += len(result['Vulnerabilities'])
                        
                        # Count by severity
                        for vuln in result['Vulnerabilities']:
                            severity = vuln.get('Severity', 'UNKNOWN')
                            if severity in summary['by_severity']:
                                summary['by_severity'][severity] += 1
            
            summary['scanners_used'].append('Trivy')
            summary['by_scanner']['Trivy'] = {
                'findings': trivy_count,
                'type': 'SCA (Dependency Analysis)'
            }
            summary['total_findings'] += trivy_count
        
        # TruffleHog results
        if self.trufflehog_results:
            trufflehog_count = len(self.trufflehog_results) if isinstance(self.trufflehog_results, list) else 0
            summary['scanners_used'].append('TruffleHog')
            summary['by_scanner']['TruffleHog'] = {
                'findings': trufflehog_count,
                'type': 'Secret Detection'
            }
            summary['total_findings'] += trufflehog_count
            summary['by_severity']['HIGH'] += trufflehog_count  # Secrets are always HIGH
        
        return summary
    
    def print_unified_report(self):
        """Print beautiful unified report"""
        summary = self.get_unified_summary()
        
        print("\n" + "="*80)
        print("📊 SECUREFLOW UNIFIED SECURITY REPORT")
        print("="*80)
        
        print(f"\n🕐 Scan Time: {summary['scan_time']}")
        print(f"🔧 Scanners Used: {', '.join(summary['scanners_used'])}")
        
        print(f"\n📈 OVERALL SUMMARY:")
        print(f"   Total Security Findings: {summary['total_findings']}")
        
        print(f"\n🎯 By Severity:")
        print(f"   🔴 CRITICAL: {summary['by_severity']['CRITICAL']}")
        print(f"   🟠 HIGH:     {summary['by_severity']['HIGH']}")
        print(f"   🟡 MEDIUM:   {summary['by_severity']['MEDIUM']}")
        print(f"   🟢 LOW:      {summary['by_severity']['LOW']}")
        
        print(f"\n🔍 By Scanner:")
        for scanner, data in summary['by_scanner'].items():
            print(f"   {scanner} ({data['type']}): {data['findings']} findings")
        
        print("\n" + "="*80)
        print("💡 RECOMMENDATIONS:")
        
        if summary['by_severity']['CRITICAL'] > 0:
            print(f"   ⚠️  {summary['by_severity']['CRITICAL']} CRITICAL issues require IMMEDIATE attention!")
        if summary['by_severity']['HIGH'] > 0:
            print(f"   🟠 {summary['by_severity']['HIGH']} HIGH severity issues should be fixed soon")
        if summary['by_severity']['MEDIUM'] > 0:
            print(f"   🟡 {summary['by_severity']['MEDIUM']} MEDIUM issues - plan to address")
        
        print("\n📁 Detailed results available in: data/scans/")
        print("="*80 + "\n")
    
    def save_unified_report(self, filename=None):
        """Save unified report to JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"unified_report_{timestamp}.json"
        
        filepath = os.path.join(self.scan_dir, filename)
        
        summary = self.get_unified_summary()
        summary['semgrep_findings'] = self.semgrep_results.get('results', []) if self.semgrep_results else []
        summary['trivy_findings'] = self.trivy_results if self.trivy_results else {}
        summary['trufflehog_findings'] = self.trufflehog_results if self.trufflehog_results else []
        
        with open(filepath, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"💾 Unified report saved to: {filepath}")
        return filepath


# Test it
if __name__ == "__main__":
    aggregator = ResultAggregator()
    aggregator.load_latest_results()
    aggregator.print_unified_report()
    aggregator.save_unified_report()
