# Security Policy

## Supported Versions

| Version | Supported          |
|---------|-----------|
| 0.2.1   | ✅ Yes     |
| 0.2.0   | ⚠️ Critical fixes only  |
| < 0.2.0 | ❌ No      |

## Security Features in v0.2.1

### Input Validation
- **SSID Validation**: Length limits (max 32 chars), safe string handling
- **BSSID Validation**: MAC address format enforcement (XX:XX:XX:XX:XX:XX)
- **Channel Validation**: Range check (1-165)
- **RSSI Validation**: Signal strength bounds (-100 to 0 dBm)
- **File Path Validation**: Path traversal prevention, file size limits (1GB max)

### SQL Injection Prevention
- **Parameterized Queries**: All database operations use prepared statements
- **Input Sanitization**: String length limits and type checking
- **Database Constraints**: CHECK constraints on numeric fields

### Cryptographic Hardening
- **PBKDF2-SHA256**: Enhanced hashing for pseudonymization with 100,000 iterations
- **Secure Salting**: Randomized salts for each observation
- **Secure Random**: Uses `secrets` module for cryptographic randomness

### Database Security
- **Foreign Key Constraints**: Enable referential integrity
- **Write-Ahead Logging**: Improved crash recovery and concurrency
- **Full Synchronization**: PRAGMA synchronous = FULL for data integrity
- **In-Memory Temp Storage**: Prevents sensitive data on disk

### File Handling
- **Safe Path Resolution**: Prevents directory traversal attacks
- **Permission Checks**: Verifies file readability before processing
- **Size Limits**: Prevents DoS attacks with oversized PCAP files
- **Error Handling**: Graceful failure on malformed packets

## Reporting Security Vulnerabilities

If you discover a security vulnerability, please email `hunterkritik-byte@github.com` with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if applicable)

**Do not** create public issues for security vulnerabilities.

## Security Best Practices

1. **Always use the latest version** - Security updates are released regularly
2. **Validate external inputs** - When processing user-supplied data
3. **Use strong permissions** - Protect PCAP files and database files (chmod 600)
4. **Keep dependencies updated** - Regularly update Scapy and other dependencies
5. **Offline processing only** - This tool does not perform active scanning
6. **Privacy by design** - Use MAC hashing and retention policies

## Known Limitations

- SSID can contain any UTF-8 characters (length limited to 32 bytes)
- RSSI values outside -100 to 0 dBm range are rejected
- PCAP file size limited to 1GB to prevent resource exhaustion
- Path traversal is prevented by resolving to absolute paths

## Compliance

- Follows OWASP Top 10 prevention guidelines
- Implements NIST-recommended cryptographic practices
- Uses parameterized SQL queries per CWE-89 standards
- Includes input validation per CWE-20 standards
