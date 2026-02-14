# My Learning Log

## Day 1 - Feb 13, 2026

### What I Did:
- Set up Kali Linux development environment
- Installed 4 security tools: Semgrep, Trivy, Grype, TruffleHog
- Created project structure
- Wrote my first Python security script

### What I Learned:
- What virtual environments are
- How to install tools with pip and apt
- Basic Python syntax
- How to make colored terminal output

### Questions I Have:
- [Write your questions here]

### What's Next:
- Learn how each security tool works
- Write code to actually run scans

## Day 2 - Feb 14, 2026 - COMPLETE! ✅

### What I Built Today:
✅ Intentionally vulnerable test app (Python + JS)
✅ SemgrepScanner Python class (200+ lines)
✅ Complete CLI tool with argparse
✅ Automated security scanning
✅ Beautiful terminal output with colors
✅ JSON result storage
✅ Vulnerability categorization

### Vulnerabilities Found (27 total):
**By Severity:**
- 🔴 ERROR: 12 findings (Critical!)
- 🟡 WARNING: 15 findings  
- 🔵 INFO: 0 findings

**By Category:**
- SQL Injection: 5
- Command Injection: 3
- XSS: 6
- Secrets (API Keys): 2
- Code Injection (eval): 4
- Path Traversal: 2
- Security Misconfiguration: 5

### Most Shocking Vulnerabilities:
1. **Hardcoded Stripe API Key** - Could steal payment info!
2. **eval() with user input** - Can execute ANY code!
3. **SQL Injection** - Can dump entire database!

### Technical Skills Learned:
- subprocess.run() to execute commands
- JSON parsing and manipulation  
- Python classes (OOP)
- argparse for CLI arguments
- Dictionary comprehensions
- File I/O operations
- Error handling
- ANSI color codes for terminal

### Code Statistics:
- Total lines written: ~400
- Functions: 15+
- Classes: 1
- Files created: 2

### Real-World Parallel:
This is EXACTLY what GitHub Secret Scanning does!
They scan every commit for API keys.

### Tomorrow's Goals:
- Add Trivy scanner
- Add TruffleHog  
- Build aggregator
- Create HTML dashboard


## Day 2 - Feb 14, 2026 - COMPLETED! ✅

### What I Built Today:
✅ Created intentionally vulnerable test application
   - Python Flask app with 8+ vulnerability types
   - JavaScript file with XSS, eval, secrets
✅ Built SemgrepScanner Python class (200+ lines)
✅ Complete CLI tool with argument parsing
✅ Automated security scanning pipeline
✅ Beautiful colored terminal output
✅ JSON result persistence
✅ Vulnerability categorization by type and severity

### Statistics:
**Vulnerabilities Found: 27 total**
- 🔴 ERROR (Critical): 12 findings
- 🟡 WARNING: 15 findings
- 🔵 INFO: 0 findings

**By Category:**
- SQL Injection: 5 findings
- Code Injection (eval): 4 findings  
- XSS: 10 findings (Other category)
- Hardcoded Secrets: 2 API keys
- Command Injection: 2 findings
- Path Traversal: 2 findings
- Security Misconfiguration: 2 findings

### Most Shocking Vulnerabilities:

**#1 - eval() with User Input (Line 70)**
```python
result = eval(expression)  # User can run ANY Python code!
```
**Impact:** Attacker could run `eval("__import__('os').system('rm -rf /')")`
and delete the entire server!

**#2 - Hardcoded Stripe API Key (Line 15)**
```python
API_KEY = "sk_live_51H8xK2L3m4N5o6P7q8R9s0T"
```
**Impact:** Anyone reading the code can steal payment credentials
and charge customers' credit cards!

**#3 - SQL Injection (Line 24)**
```python
sql = f"SELECT * FROM users WHERE name = '{query}'"
```
**Impact:** Attacker inputs: `' OR '1'='1' --`
Result: Returns ALL users, bypasses authentication!

### Technical Skills Learned:
- `subprocess.run()` - Execute external commands from Python
- JSON parsing with `json.loads()` and `json.dumps()`
- Python classes and OOP (Object-Oriented Programming)
- `argparse` module for CLI arguments
- File I/O with `open()`, `read()`, `write()`
- Dictionary comprehensions: `{k: v for k, v in items}`
- Error handling with `try/except`
- ANSI color codes for beautiful terminal output
- Project structure and modular code organization

### Code Written Today:
- **Total Lines:** ~400 lines of Python
- **Functions:** 15+
- **Classes:** 1 (SemgrepScanner)
- **Modules:** 2 (semgrep_scanner.py, main.py)

### Real-World Comparison:
This is EXACTLY what professional tools do:
- **GitHub Secret Scanning** - Scans commits for API keys
- **Snyk Code** - SAST scanning in CI/CD
- **GitLab Security Dashboard** - Aggregates security findings

Companies pay $50k-100k/year for engineers who can build this!

### Questions Answered:

**Q: How does Semgrep actually work?**
A: It parses code into an Abstract Syntax Tree (AST) and matches
   patterns against security rules. It understands code semantically,
   not just text matching.

**Q: Why save to JSON?**
A: JSON is machine-readable, can be parsed by other tools,
   easy to query, and is the standard format for API data exchange.

**Q: What's the difference between ERROR and WARNING?**
A: ERROR = Definitely exploitable, immediate fix required
   WARNING = Potentially dangerous, should review
   INFO = Best practice violation, lower priority

### What I Learned About Security:

1. **Defense in Depth:** Never trust user input ANYWHERE
2. **Secrets Management:** Never hardcode credentials in code
3. **Parameterized Queries:** Always use for SQL to prevent injection
4. **Input Validation:** Sanitize and validate ALL user input
5. **Least Privilege:** Don't run as root, don't use debug=True in prod

### Tomorrow's Plan (Day 3):
- [ ] Add Trivy scanner for dependency vulnerabilities
- [ ] Add TruffleHog for git history secret scanning
- [ ] Build result aggregator to combine multiple scanners
- [ ] Create risk scoring system
- [ ] Build HTML dashboard for results

### Reflections:
**Most Exciting:** Seeing 27 real vulnerabilities detected automatically!

**Most Challenging:** Understanding how subprocess works with JSON output

**Proudest Moment:** When the tool ran successfully and found all the bugs I intentionally created!

**What I Want to Learn Next:** How to actually FIX these vulnerabilities,
not just detect them. Maybe add auto-fix suggestions?
