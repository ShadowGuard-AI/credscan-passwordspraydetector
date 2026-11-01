import argparse
import re
import logging
import sys
import tldextract  # Ensure this is installed: pip install tldextract

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def setup_argparse():
    """Sets up the argument parser for the command-line interface."""
    parser = argparse.ArgumentParser(
        description="Detects password spraying attacks and credential leaks."
    )

    # Subparsers for different functionalities
    subparsers = parser.add_subparsers(
        title="Commands", dest="command", help="Available commands"
    )

    # Password spraying detection subparser
    spray_parser = subparsers.add_parser(
        "spray", help="Detect password spraying attacks from log files."
    )
    spray_parser.add_argument(
        "log_file", type=str, help="Path to the authentication log file."
    )
    spray_parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Threshold for failed login attempts from the same IP. Spraying is flagged only when failures from one IP reach this count across distinct accounts; the same count against fewer accounts is flagged as brute force.",
    )

    # Credential leak detection subparser
    leak_parser = subparsers.add_parser(
        "leak", help="Scan files for potential credential leaks."
    )
    leak_parser.add_argument(
        "file_path", type=str, help="Path to the file to scan for leaks."
    )
    leak_parser.add_argument(
        "--domains",
        type=str,
        nargs="*",
        help="List of domains to flag in URLs (e.g., example.com).",
    )

    return parser


def detect_password_spraying(log_file, threshold):
    """
    Detects password spraying attacks by analyzing failed login attempts.

    Args:
        log_file (str): Path to the authentication log file.
        threshold (int): Number of failed attempts from an IP before flagging.
            Spraying is flagged only when the failures from one IP reach
            the threshold across distinct accounts. Failures reaching the
            threshold against fewer accounts are flagged as brute force
            against those accounts instead, not as spraying.
    """
    try:
        ip_failed_attempts = {}
        ip_accounts = {}
        with open(log_file, "r") as f:
            for line in f:
                #  Match failed login attempts, capturing the account as
                #  well as the IP. Adjust regex based on your log format.
                # I accept only these two failure wordings, with the account
                # before the IP. A log that writes its fields in another order,
                # or words a failure differently, contributes nothing here.
                match = re.search(
                    r"(?:Failed login|Authentication failure) for (?:user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                    line,
                )
                if match:
                    account = match.group(1)
                    ip = match.group(2)
                    ip_failed_attempts[ip] = ip_failed_attempts.get(ip, 0) + 1
                    ip_accounts.setdefault(ip, set()).add(account)

        # Spraying means one IP failing against many accounts, so the
        # spraying flag needs the threshold met in distinct accounts,
        # not just in raw failure count.
        spraying_ips = [
            ip
            for ip, accounts in ip_accounts.items()
            if len(accounts) >= threshold
        ]
        # The same raw count against fewer accounts is a different
        # attack shape, so it gets its own label instead of borrowing
        # the spraying one.
        brute_force_ips = [
            ip
            for ip, count in ip_failed_attempts.items()
            if count >= threshold and ip not in spraying_ips
        ]

        if spraying_ips:
            logging.warning(
                f"Potential password spraying attack detected.  The following IPs have failed against at least the threshold ({threshold}) distinct accounts:"
            )
            for ip in spraying_ips:
                logging.warning(
                    f"IP: {ip} - Failed attempts: {ip_failed_attempts[ip]} - Distinct accounts: {len(ip_accounts[ip])}"
                )
        if brute_force_ips:
            logging.warning(
                f"Potential brute force attack detected.  The following IPs have exceeded the threshold ({threshold}) against fewer distinct accounts, so this is not spraying:"
            )
            for ip in brute_force_ips:
                logging.warning(
                    f"IP: {ip} - Failed attempts: {ip_failed_attempts[ip]} - Distinct accounts: {len(ip_accounts[ip])}"
                )
        if not spraying_ips and not brute_force_ips:
            logging.info("No password spraying attacks detected based on the threshold.")
        return True

    except FileNotFoundError:
        logging.error(f"Log file not found: {log_file}")
        return False
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return False


def detect_credential_leaks(file_path, domains=None):
    """
    Scans a file for potential credential leaks using regex and domain parsing.

    Args:
        file_path (str): Path to the file to scan.
        domains (list, optional): List of domains to flag. Defaults to None.
    """
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()

        # Regex patterns for common credentials and sensitive information. Customize and expand as needed.
        patterns = {
            # The password keyword group below is non-capturing on
            # purpose: with a capturing group, findall returns the
            # group ("password") instead of the whole match, so the
            # report named the keyword and never showed the leaked
            # value it was supposed to surface.
            "API Key": r"[A-Za-z0-9_-]{32,45}",  # Example: long alphanumeric string
            "Password": r"(?:password|pwd)\s*[:=]\s*[\"']?[\w\d!@#$%^&*()_+=\-`~\[\]\{\}\|;':\",\.\/<>\?]+[\"']?", #Basic password detection
            "Email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Secret Key": r"[sS][ecret]*\_?[Kk][eys]*\s*[:=]\s*[\"']?[\w\d!@#$%^&*()_+=\-`~\[\]\{\}\|;':\",\.\/<>\?]+[\"']?"
        }

        # Iterate and search for leaks
        for key, pattern in patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                logging.warning(f"Potential {key} leak(s) found:")
                for match in matches:
                    # I log the matched text in full, including the value after a
                    # password keyword. That is the leak this command exists to
                    # surface, and it means the log itself becomes sensitive.
                    logging.warning(f"  - {match}")

        # Domain parsing for suspicious URLs
        if domains:
            url_pattern = r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
            urls = re.findall(url_pattern, content)
            for url in urls:
                ext = tldextract.extract(url)
                # I compare the registered domain only. A URL on a subdomain
                # of a listed domain matches, and a listed subdomain on its
                # own never does, because the subdomain part is dropped here.
                domain = ext.domain + "." + ext.suffix
                if domain in domains:
                    logging.warning(f"Suspicious URL found with domain {domain}: {url}")

        return True
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return False
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return False


def main():
    """
    Main function to parse arguments and call the appropriate functions.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Both detectors used to swallow a missing input file and let
    # main exit 0, so a scripted run could not tell a failed scan
    # from a clean one. A failed scan now exits 1; findings are
    # still reported as warnings, not as a failed exit.
    if args.command == "spray":
        if not detect_password_spraying(args.log_file, args.threshold):
            sys.exit(1)
    elif args.command == "leak":
        if not detect_credential_leaks(args.file_path, args.domains):
            sys.exit(1)


if __name__ == "__main__":
    main()

# Usage Examples:

# Password Spraying Detection:
#   python credscan.py spray auth.log --threshold 10

# Credential Leak Detection:
#   python credscan.py leak config.ini
#   python credscan.py leak code.py --domains example.com internal.corp