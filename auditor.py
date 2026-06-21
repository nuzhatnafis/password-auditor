
"""
Password Security Auditor
Checks password strength, patterns, and common password usage.
"""

import re
import hashlib
import argparse
import requests
import getpass
from collections import Counter

def calculate_entropy(password):
    """Calculate password entropy in bits."""
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    if charset == 0:
        return 0
    import math
    return round(len(password) * math.log2(charset), 2)

def check_pwned(password):
    """Check if password has been in a data breach using HaveIBeenPwned API (k-anonymity)."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5
        )
        hashes = (line.split(":") for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0
    except requests.RequestException:
        return -1  # API unavailable

def check_strength(password):
    """Evaluate password strength across multiple criteria."""
    score = 0
    issues = []
    strengths = []

    # Length check
    length = len(password)
    if length < 8:
        issues.append("Too short (minimum 8 characters)")
    elif length < 10:
        score += 1
        issues.append("Consider using 12+ characters for better security")
    elif length < 12:
        score += 2
        strengths.append(f"Good length ({length} characters)")
    else:
        score += 3
        strengths.append(f"Excellent length ({length} characters)")

    # Character class checks
    if re.search(r'[a-z]', password):
        score += 1
        strengths.append("Contains lowercase letters")
    else:
        issues.append("Missing lowercase letters")

    if re.search(r'[A-Z]', password):
        score += 1
        strengths.append("Contains uppercase letters")
    else:
        issues.append("Missing uppercase letters")

    if re.search(r'[0-9]', password):
        score += 1
        strengths.append("Contains numbers")
    else:
        issues.append("Missing numbers")

    if re.search(r'[^a-zA-Z0-9]', password):
        score += 2
        strengths.append("Contains special characters")
    else:
        issues.append("Missing special characters (!@#$%^&*)")

    # Pattern checks
    if re.search(r'(.)\1{2,}', password):
        score -= 1
        issues.append("Contains repeated characters (aaa, 111)")

    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde)', password.lower()):
        score -= 1
        issues.append("Contains sequential characters")

    common_bases = ['password', 'qwerty', 'letmein', 'welcome', 'admin',
                    'login', 'monkey', 'dragon', 'master', 'sunshine']
    for base in common_bases:
        if base in password.lower():
            score -= 2
            issues.append(f"Contains common word: '{base}'")
            break

    # Keyboard patterns
    keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '!@#$%^']
    for pattern in keyboard_patterns:
        if pattern in password.lower():
            score -= 1
            issues.append(f"Contains keyboard pattern: '{pattern}'")
            break

    # Score to label
    score = max(0, score)
    if score <= 2:
        rating = "VERY WEAK"
    elif score <= 4:
        rating = "WEAK"
    elif score <= 6:
        rating = "MODERATE"
    elif score <= 8:
        rating = "STRONG"
    else:
        rating = "VERY STRONG"

    entropy = calculate_entropy(password)

    return {
        "score": score,
        "rating": rating,
        "entropy": entropy,
        "length": length,
        "strengths": strengths,
        "issues": issues
    }

def audit_password(password, check_breach=True):
    """Full password audit."""
    print(f"\n  {'='*50}")
    print(f"  PASSWORD AUDIT REPORT")
    print(f"  {'='*50}")
    print(f"  Length  : {len(password)} characters")

    result = check_strength(password)

    print(f"  Rating  : {result['rating']}")
    print(f"  Score   : {result['score']}/10")
    print(f"  Entropy : {result['entropy']} bits")

    if result["strengths"]:
        print(f"\n  ✓ STRENGTHS:")
        for s in result["strengths"]:
            print(f"    + {s}")

    if result["issues"]:
        print(f"\n  ✗ ISSUES:")
        for i in result["issues"]:
            print(f"    - {i}")

    if check_breach:
        print(f"\n  [*] Checking HaveIBeenPwned database...")
        count = check_pwned(password)
        if count == -1:
            print(f"  [!] Could not reach HIBP API")
        elif count == 0:
            print(f"  ✓ Not found in known breaches")
        else:
            print(f"  ✗ FOUND IN {count:,} DATA BREACHES — CHANGE IMMEDIATELY")

    print(f"\n  {'='*50}\n")
    return result

def main():
    parser = argparse.ArgumentParser(
        description="Password Security Auditor"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--password",
                       help="Password to audit (use -i for interactive)")
    group.add_argument("-i", "--interactive", action="store_true",
                       help="Enter password interactively (hidden input)")
    parser.add_argument("--no-breach-check", action="store_true",
                        help="Skip HaveIBeenPwned check")
    args = parser.parse_args()

    if args.interactive:
        password = getpass.getpass("  Enter password to audit: ")
    else:
        password = args.password

    audit_password(password, check_breach=not args.no_breach_check)

if __name__ == "__main__":
    main()