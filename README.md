![Banner](banner.png)

# credscan-PasswordSprayDetector
Analyzes authentication logs to detect password spraying attacks. It identifies patterns of failed login attempts across multiple accounts originating from the same source IP: the account named in each log line is parsed, failures are grouped by source IP, and spraying is flagged only when the failures from one IP reach the threshold across distinct accounts. Failures that reach the threshold against fewer accounts, for example repeated failures against a single account, are flagged separately as a potential brute force attack, not as spraying. - Focused on Scans code repositories, log files, and other text-based artifacts for inadvertently exposed credentials, API keys, or other sensitive information. Uses regular expressions and heuristics to identify potential leaks. Includes domain parsing to flag suspicious URLs.

## Install
`git clone https://github.com/ShadowStrikeHQ/credscan-passwordspraydetector`

## Usage
`./credscan-passwordspraydetector [params]`

## Parameters
- `-h`: Show help message and exit
- `--threshold`: Threshold for failed login attempts from the same IP. Spraying requires this count across distinct accounts; the same count against fewer accounts is reported as brute force.
- `--domains`: No description provided

## License
Copyright (c) ShadowStrikeHQ
