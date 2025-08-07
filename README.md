# check_airlock_letsencrypt

Nagios/Naemon plugin to check Airlock Let's Encrypt certificate expiration.

## Overview

This plugin checks the expiry of all ACME-managed (Let's Encrypt) certificates on an Airlock Gateway via its REST API. It is designed for integration with Nagios, Naemon, or Thruk monitoring systems.

## Features

- Connects to Airlock Gateway REST API
- Finds all virtual hosts using ACME/Let's Encrypt certificates
- Checks certificate expiry dates for each domain
- Returns Nagios-compatible status and performance data

## Requirements

- Python 3.6+
- `requests` library

Install dependencies (if needed):

```sh
pip install requests
```

## Usage

Place the script in your Nagios/Thruk plugins directory.

```sh
python3 check_airlock_letsencrypt.py --airlock-host <HOST> --api-token <TOKEN> [options]
```

### Arguments

- `--airlock-host` (required): Airlock Gateway hostname (FQDN or IP)
- `--api-token` (required): Bearer API Token for Airlock REST API
- `-w`, `--warning`: Warning threshold in days (default: 30)
- `-c`, `--critical`: Critical threshold in days (default: 15)
- `-t`, `--timeout`: Plugin timeout in seconds (default: 50)
- `-v`, `--version`: Show version and exit

### Example

```sh
python3 check_airlock_letsencrypt.py --airlock-host airlock.example.com --api-token ABCDEFGHIJKL -w 20 -c 10
```

## Output

- **OK**: All ACME certs valid  
  `OK - All ACME certs valid - domain1.example.com(45d), domain2.example.com(32d)`
- **WARNING**: At least one cert is below the warning threshold  
  `WARNING - domain2.example.com(15d)`
- **CRITICAL**: At least one cert is below the critical threshold  
  `CRITICAL - domain3.example.com(5d)`
- **Performance Data**:  
  `| min_days=5;;;;`

## Exit Codes

- `0`: OK
- `1`: WARNING
- `2`: CRITICAL
- `3`: UNKNOWN

## License

MIT License

##
