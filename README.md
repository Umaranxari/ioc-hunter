# IOC-Hunter

**A regex-based threat detection engine for web server logs.**

## The Problem
During an incident response scenario, I was handed a 5GB Apache access log and asked to "find the SQL injection." Running multiple `grep` commands for different patterns was tedious and error-prone. I needed a tool that could:
1.  Apply a library of known attack signatures (IOCs) in a single pass.
2.  Prioritize alerts by severity (CRITICAL vs LOW).
3.  Handle large files without loading them into memory.

## How It Works
IOC-Hunter pre-compiles a set of regex signatures from `signatures.json` and streams the log file line-by-line. This allows it to process massive log files with minimal RAM usage.

## Features
*   **JSON-based Signatures**: Easy to add new CVE patterns without touching the code.
*   **Severity Tagging**: distinguishes between simple scanning (LOW) and active exploitation (CRITICAL).
*   **Performance**: Uses Python's `re` module with pre-compilation for speed.

## Usage

1. **Define your signatures** in `signatures.json`:
   ```json
   {
       "name": "Log4Shell",
       "pattern": "\\$\\{jndi:",
       "severity": "CRITICAL"
   }
   ```

2. **Run the hunter**:
   ```bash
   python3 hunter.py /var/log/apache2/access.log
   ```

## Demo Output
```text
[!] ALERT: SQL Injection (Union-Based) detected
    Sev: CRITICAL | Line: 402 | Time: 10/Oct/2023:13:55:36
    Payload: GET /search.php?q=admin' UNION SELECT 1, database(), 3-- ...
```

