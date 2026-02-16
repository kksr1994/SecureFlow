#!/usr/bin/env python3
"""
TruffleHog Scanner Module
Scans for secrets in files and git history
"""

import subprocess
import json
import os
from datetime import datetime
from pathlib import Path


class TruffleHogScanner:
    """Class to handle TruffleHog scanning operations"""
    
    def __init__(self, target_path, output_dir="data/scans"):
        """
        Initialize the scanner
        
        Args:
            target_path: Path to scan
            output_dir: Where to save results
        """
        self.target_path = target_path
        self.output_dir = output_dir
        self.results = []
        
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    def run_scan(self):
        """Run TruffleHog scan"""
        print(f"🔍 Running TruffleHog scan on: {self.target_path}")
        
        # Check if it's a git repo
        is_git_repo = os.path.exists(os.path.join(self.target_path, '.git'))
        
        if not is_git_repo:
            print("⚠ Not a git repository - initializing temporary git repo...")
            try:
                # Initialize git temporarily
                subprocess.run(['git', 'init'], cwd=self.target_path, capture_output=True, check=True)
                subprocess.run(['git', 'add', '.'], cwd=self.target_path, capture_output=True, check=True)
                subprocess.run(['git', 'config', 'user.email', 'scan@secureflow.local'], cwd=self.target_path, capture_output=True)
                subprocess.run(['git', 'config', 'user.name', 'SecureFlow Scanner'], cwd=self.target_path, capture_output=True)
                subprocess.run(['git', 'commit', '-m', 'temp scan'], cwd=self.target_path, capture_output=True, check=True)
                temp_git = True
            except:
                print("⚠ Could not initialize git - skipping TruffleHog scan")
                return []
        else:
            temp_git = False
        
        try:
            # Build the command
            command = [
                'trufflehog',
                '--regex',
                '--entropy=True',
                '--max_depth=50',
                self.target_path
            ]
            
            # Run the command
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=30
            )
            
            # Parse output
            if result.stdout and result.stdout.strip():
                findings = result.stdout.strip().split('\n')
                
                secrets_found = []
                current_secret = {}
                
                for line in findings:
                    if line.startswith('~~~~~'):
                        if current_secret:
                            secrets_found.append(current_secret)
                        current_secret = {}
                    elif ':' in line and current_secret is not None:
                        try:
                            key, value = line.split(':', 1)
                            current_secret[key.strip()] = value.strip()
                        except:
                            continue
                
                if current_secret:
                    secrets_found.append(current_secret)
                
                self.results = secrets_found
                
                # Clean up temp git if we created it
                if temp_git:
                    try:
                        import shutil
                        git_dir = os.path.join(self.target_path, '.git')
                        if os.path.exists(git_dir):
                            shutil.rmtree(git_dir)
                    except:
                        pass
                
                print(f"✓ Scan completed! Found {len(self.results)} potential secrets")
                return self.results
            else:
                # Clean up temp git
                if temp_git:
                    try:
                        import shutil
                        git_dir = os.path.join(self.target_path, '.git')
                        if os.path.exists(git_dir):
                            shutil.rmtree(git_dir)
                    except:
                        pass
                
                print("✓ No secrets found!")
                return []
                
        except subprocess.TimeoutExpired:
            print("⚠ TruffleHog scan timed out")
            return []
        except Exception as e:
            print(f"✗ Error running TruffleHog: {e}")
            return []
    
    def save_results(self, filename=None):
        """Save scan results"""
        if not self.results:
            return None
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"trufflehog_scan_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"💾 Results saved to: {filepath}")
        return filepath
    
    def get_summary(self):
        """Get summary of findings"""
        if not self.results:
            return {
                'total_secrets': 0,
                'by_type': {},
                'high_entropy': 0
            }
        
        type_count = {}
        high_entropy = 0
        
        for finding in self.results:
            # Try to categorize by content
            finding_type = 'Unknown'
            
            if any(k in str(finding).lower() for k in ['reason', 'Reason']):
                reason = finding.get('Reason', finding.get('reason', ''))
                if 'high entropy' in reason.lower():
                    high_entropy += 1
                    finding_type = 'High Entropy String'
                elif 'regex' in reason.lower():
                    finding_type = 'Pattern Match'
            
            type_count[finding_type] = type_count.get(finding_type, 0) + 1
        
        return {
            'total_secrets': len(self.results),
            'by_type': type_count,
            'high_entropy': high_entropy,
            'scanned_path': self.target_path,
            'scan_time': datetime.now().isoformat()
        }
    
    def print_findings(self, max_findings=10):
        """Print findings"""
        if not self.results:
            print("\n✓ No secrets found!")
            return
        
        print("\n" + "="*80)
        print(f"📊 TRUFFLEHOG SCAN RESULTS")
        print("="*80)
        
        summary = self.get_summary()
        print(f"\n📈 Summary:")
        print(f"   Total Secrets Found: {summary['total_secrets']}")
        print(f"   High Entropy Strings: {summary['high_entropy']}")
        
        if summary['by_type']:
            print(f"\n📂 By Type:")
            for secret_type, count in sorted(summary['by_type'].items(), key=lambda x: x[1], reverse=True):
                print(f"   {secret_type}: {count}")
        
        print(f"\n🔍 Detailed Findings (showing {min(max_findings, len(self.results))} of {len(self.results)}):\n")
        
        for idx, finding in enumerate(self.results[:max_findings], 1):
            reason = finding.get('Reason', finding.get('reason', 'Unknown'))
            filepath = finding.get('path', finding.get('Path', 'Unknown'))
            
            print(f"🔑 Secret #{idx}")
            print(f"   Reason: {reason}")
            print(f"   File: {filepath}")
            print()
        
        if len(self.results) > max_findings:
            print(f"   ... and {len(self.results) - max_findings} more secrets")
            print(f"   💡 Tip: Use --all flag to see all findings\n")


# Example usage
if __name__ == "__main__":
    scanner = TruffleHogScanner("test-apps/vulnerable-app")
    scanner.run_scan()
    scanner.print_findings()
    scanner.save_results()
    
    summary = scanner.get_summary()
    print(f"\n📊 Final Summary:")
    print(json.dumps(summary, indent=2))
