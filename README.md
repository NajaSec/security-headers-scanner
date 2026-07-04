
# Security Header Analyzer

Python tool for scanning HTTP security headers with weighted scoring.

## Features
- Checks 9 security headers (HSTS, CSP, X-Frame-Options, etc.)
- Weighted scoring system (A+ to F ratings)
- Color-coded terminal output
- Provides fix recommendations
- SSL/TLS & info disclosure checks
- Retry mechanism with timeout

## Installation
```bash
pip install requests colorama urllib3
```

## Usage
```bash
python scanner.py <url> [options]
```

### Options
| Option | Description |
|--------|-------------|
| `-t, --timeout` | Timeout in seconds (default: 15) |
| `-m, --method` | HTTP method (default: GET) |
| `-r, --retries` | Retry count (default: 2) |
| `-ua, --user-agent` | Custom User-Agent |

### Example
```bash
python Http_Header.py example.com
python Http_Header.py example.com -t 30 -m POST
```

## Scoring
| Score | Rating |
|-------|--------|
| 90-100% | A+ |
| 75-89% | A |
| 60-74% | B |
| 40-59% | C |
| <40% | F |

**Note:** The issue count (Critical/High/Medium) is informational only and not the primary security metric. Focus on the overall score and specific header recommendations.

## Requirements
- Python 3.6+

## License
MIT
```
