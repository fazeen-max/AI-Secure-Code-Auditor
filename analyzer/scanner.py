import re


def scan_code(code):
    findings = []

    lines = code.splitlines()

    for line_number, line in enumerate(lines, start=1):

        # SQL Injection
        if re.search(
            r'execute\s*\(\s*["\'].*(%s|\+|\{).*["\']',
            line,
            re.IGNORECASE
        ):
            findings.append({
                "type": "SQL Injection",
                "severity": "HIGH",
                "line": line_number,
                "code": line.strip(),
                "message": "SQL query appears to be constructed using dynamic user-controlled data.",
                "recommendation": "Use parameterized queries instead of building SQL statements with string concatenation or interpolation."
            })


        # Hardcoded password or secret
        if re.search(
            r'(password|passwd|secret|api[_-]?key)\s*=\s*["\'][^"\']+["\']',
            line,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Hardcoded Secret",
                "severity": "HIGH",
                "line": line_number,
                "code": line.strip(),
                "message": "A possible password, secret, or API key is hardcoded in the source code.",
                "recommendation": "Store secrets in environment variables or a secure secret-management system."
            })


        # Dangerous command execution
        if re.search(
            r'\b(os\.system|subprocess\.Popen|subprocess\.call|subprocess\.run)\s*\(',
            line,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Command Execution",
                "severity": "HIGH",
                "line": line_number,
                "code": line.strip(),
                "message": "The code executes an operating-system command.",
                "recommendation": "Validate all external input carefully and avoid passing untrusted data directly to system commands."
            })


        # Python eval/exec
        if re.search(
            r'\b(eval|exec)\s*\(',
            line,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Dynamic Code Execution",
                "severity": "HIGH",
                "line": line_number,
                "code": line.strip(),
                "message": "Dynamic execution can execute attacker-controlled code when supplied with untrusted input.",
                "recommendation": "Avoid eval() and exec() with untrusted input. Use safer parsing or explicit logic."
            })


        # Weak MD5 hashing
        if re.search(
            r'\bmd5\s*\(',
            line,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Weak Cryptography",
                "severity": "MEDIUM",
                "line": line_number,
                "code": line.strip(),
                "message": "MD5 is considered cryptographically weak for security-sensitive hashing.",
                "recommendation": "Use a modern cryptographic hash such as SHA-256 when appropriate."
            })


        # Weak SHA-1 hashing
        if re.search(
            r'\bsha1\s*\(',
            line,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Weak Cryptography",
                "severity": "MEDIUM",
                "line": line_number,
                "code": line.strip(),
                "message": "SHA-1 is considered weak for modern security applications.",
                "recommendation": "Use a stronger modern hashing algorithm such as SHA-256 when appropriate."
            })


        # Path traversal pattern
        if "../" in line or "..\\" in line:
            findings.append({
                "type": "Path Traversal",
                "severity": "HIGH",
                "line": line_number,
                "code": line.strip(),
                "message": "The code contains a path traversal pattern.",
                "recommendation": "Validate and normalize file paths and restrict file access to an allowed directory."
            })


        # Insecure HTTP
        if re.search(
            r'http://',
            line,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Insecure HTTP",
                "severity": "LOW",
                "line": line_number,
                "code": line.strip(),
                "message": "The code contains a non-encrypted HTTP URL.",
                "recommendation": "Use HTTPS when transmitting sensitive or security-relevant data."
            })
            # Insecure Deserialization
        if re.search(
            r'\bpickle\.(load|loads)\s*\(',
            line,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Insecure Deserialization",
                "severity": "HIGH",
                "line": line_number,
                "code": line.strip(),
                "message": "Pickle can execute arbitrary code when loading untrusted serialized data.",
                "recommendation": "Never deserialize untrusted data with pickle. Use a safer data format such as JSON."
            })


        # Weak Randomness for Security
        if re.search(
            r'\brandom\.(random|randint|choice|randrange)\s*\(',
            line,
            re.IGNORECASE
        ) and re.search(
            r'(token|password|secret|key|session|otp)',
            line,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Weak Randomness",
                "severity": "MEDIUM",
                "line": line_number,
                "code": line.strip(),
                "message": "A non-cryptographic random generator may be used for security-sensitive data.",
                "recommendation": "Use Python's secrets module for security-sensitive tokens, passwords, and authentication values."
            })


    return findings