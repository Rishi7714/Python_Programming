"""
╔══════════════════════════════════════════════════════════════╗
║         PASSWORD STRENGTH CHECKER — Security Analysis Tool   ║
║                                                              ║
║  Author  : Rishabh Sankhla                                   ║
║  GitHub  : github.com/rishi7714                              ║
║  LinkedIn: linkedin.com/in/rishabhsankhla771401              ║
║  Purpose : Analyse password strength, check complexity       ║
║            rules, estimate crack time, and check against     ║
║            HaveIBeenPwned breach database                    ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
  # Interactive mode (prompts for password securely)
  python3 password_strength.py

  # Check a single password
  python3 password_strength.py -p "MyPassword123!"

  # Analyse a list of passwords from file
  python3 password_strength.py -f passwords.txt

  # Check against HaveIBeenPwned (requires internet)
  python3 password_strength.py -p "password123" --hibp

  # Generate a strong password
  python3 password_strength.py --generate

  # Generate with custom length
  python3 password_strength.py --generate --length 20

  # Batch check file + save report
  python3 password_strength.py -f passwords.txt --output report.json

  # Check with custom policy
  python3 password_strength.py -p "test" --min-length 12 --require-special

DISCLAIMER:
  For security auditing, education, and password policy enforcement.
  Never store or transmit passwords in plain text outside of authorised use.
"""

import re
import sys
import os
import json
import math
import hashlib
import string
import secrets
import argparse
import getpass
import urllib.request
import urllib.error
from datetime import datetime


# ─────────────────────────────────────────────────────────────
# COLOUR OUTPUT
# ─────────────────────────────────────────────────────────────
class Colour:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RESET  = '\033[0m'

    @staticmethod
    def disable():
        Colour.RED = Colour.GREEN = Colour.YELLOW = ''
        Colour.BLUE = Colour.CYAN = Colour.WHITE = ''
        Colour.BOLD = Colour.DIM = Colour.RESET = ''


# ─────────────────────────────────────────────────────────────
# COMMON PASSWORDS LIST (top 200 most used)
# ─────────────────────────────────────────────────────────────
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "111111",
    "123123", "admin", "letmein", "welcome", "monkey",
    "1234", "dragon", "master", "pass", "login",
    "sunshine", "princess", "football", "shadow", "superman",
    "michael", "baseball", "iloveyou", "trustno1", "batman",
    "passw0rd", "password1", "password123", "p@ssword", "p@ss",
    "pa$$word", "p@$$w0rd", "secret", "test", "guest",
    "root", "toor", "admin123", "qwerty123", "abc",
    "qazwsx", "zxcvbn", "asdfgh", "654321", "55555",
    "555555", "696969", "77777", "777777", "999999",
    "99999999", "88888888", "12341234", "11111111", "00000000",
    "123321", "1q2w3e4r", "1q2w3e", "qweasd", "q1w2e3r4",
    "superman1", "batman1", "spiderman", "pokemon", "naruto",
    "whatever", "nothing", "cheese", "cheese1", "coffee",
    "chocolate", "cookie", "computer", "windows", "internet",
    "google", "facebook", "twitter", "amazon", "netflix",
    "india123", "india@123", "delhi", "mumbai", "bangalore",
    "india", "bharat", "jai hind", "cricket", "dhoni",
    "virat", "sachin", "rohit", "modi", "gandhi",
    "ram123", "shiva", "krishna", "welcome1", "welcome@1",
    "changeme", "changeme1", "newpass", "newpassword",
    "mypassword", "password!", "password@", "password#",
    "123456!", "123456@", "qwerty!", "qwerty@1",
}

# ─────────────────────────────────────────────────────────────
# KEYBOARD PATTERNS — Sequential and keyboard walk patterns
# ─────────────────────────────────────────────────────────────
KEYBOARD_PATTERNS = [
    # Horizontal rows
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "poiuytrewq", "lkjhgfdsa", "mnbvcxz",
    # Number sequences
    "1234567890", "0987654321",
    "12345", "23456", "34567", "45678", "56789",
    "54321", "43210",
    # Diagonal patterns
    "qweasdzxc", "qweadszxc",
    "1qaz", "2wsx", "3edc", "4rfv",
    "1qazxsw2", "!qaz@wsx",
    # Common patterns
    "abcdefgh", "abcdef", "abcd",
    "zyxwvuts", "zyxwvu",
    "aaaaaa", "bbbbbb", "cccccc",
    "aabbaabb", "ababab",
]

# ─────────────────────────────────────────────────────────────
# LEET SPEAK MAP — For detecting leet-speak obfuscation
# ─────────────────────────────────────────────────────────────
LEET_MAP = {
    '0': 'o', '1': 'i', '1': 'l', '3': 'e',
    '4': 'a', '5': 's', '6': 'g', '7': 't',
    '8': 'b', '9': 'g', '@': 'a', '$': 's',
    '!': 'i', '|': 'l', '+': 't', '(': 'c',
}


# ─────────────────────────────────────────────────────────────
# CRACK TIME ESTIMATION
# ─────────────────────────────────────────────────────────────

# Assumed attack speeds (guesses per second)
ATTACK_SPEEDS = {
    "Online (throttled)":     10,          # Online attack with throttling
    "Online (no throttle)":   1_000,       # Online attack, no rate limit
    "Offline (slow hash)":    10_000,      # Offline, bcrypt/Argon2
    "Offline (MD5/SHA1)":     1_000_000_000_000,  # Fast hashing (12 billion/s GPU)
}

def estimate_crack_time(entropy_bits: float) -> dict:
    """
    Estimate crack time for different attack scenarios
    based on password entropy.
    """
    # Number of combinations = 2^entropy
    combinations = 2 ** entropy_bits
    times = {}

    for scenario, speed in ATTACK_SPEEDS.items():
        seconds = combinations / speed / 2  # Average case = half of total combinations

        if seconds < 1:
            label = "Instantly"
        elif seconds < 60:
            label = f"{seconds:.1f} seconds"
        elif seconds < 3600:
            label = f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            label = f"{seconds/3600:.1f} hours"
        elif seconds < 2_592_000:
            label = f"{seconds/86400:.1f} days"
        elif seconds < 31_536_000:
            label = f"{seconds/2_592_000:.1f} months"
        elif seconds < 3_153_600_000:
            label = f"{seconds/31_536_000:.1f} years"
        elif seconds < 3_153_600_000_000:
            label = f"{seconds/3_153_600_000:.1f} thousand years"
        elif seconds < 3_153_600_000_000_000:
            label = f"{seconds/3_153_600_000_000:.1f} million years"
        else:
            label = "Longer than the age of the universe 🔒"

        times[scenario] = {
            "seconds": seconds,
            "label":   label,
        }

    return times


def calculate_entropy(password: str) -> float:
    """
    Calculate password entropy in bits.
    Entropy = log2(charset_size ^ length) = length * log2(charset_size)
    """
    charset_size = 0

    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'[0-9]', password):
        charset_size += 10
    if re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?/\\`~"\']', password):
        charset_size += 32
    if re.search(r'[ ]', password):
        charset_size += 1

    if charset_size == 0:
        return 0.0

    return len(password) * math.log2(charset_size)


# ─────────────────────────────────────────────────────────────
# HAVEIBEENPWNED API
# ─────────────────────────────────────────────────────────────

def check_hibp(password: str) -> dict:
    """
    Check password against HaveIBeenPwned using k-Anonymity.

    The password is NEVER sent in plain text.
    We send only the first 5 characters of the SHA-1 hash.
    HIBP returns all hashes starting with those 5 chars.
    We check locally if our full hash is in the list.
    """
    result = {
        "checked":      False,
        "pwned":        False,
        "count":        0,
        "error":        "",
    }

    try:
        # SHA-1 hash of the password
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        # Query HIBP API — only send first 5 chars
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "PasswordStrengthChecker/1.0 (Educational Tool)",
                "Add-Padding": "true",  # Adds noise to prevent traffic analysis
            }
        )

        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")

        # Parse response — each line: SUFFIX:COUNT
        result["checked"] = True
        for line in body.splitlines():
            if ":" in line:
                hash_suffix, count = line.split(":", 1)
                if hash_suffix.strip().upper() == suffix:
                    result["pwned"] = True
                    result["count"] = int(count.strip())
                    break

    except urllib.error.URLError as e:
        result["error"] = f"Network error: {e.reason}"
    except Exception as e:
        result["error"] = f"Error: {str(e)}"

    return result


# ─────────────────────────────────────────────────────────────
# PASSWORD ANALYSIS ENGINE
# ─────────────────────────────────────────────────────────────

def analyse_password(password: str, policy: dict = None, check_hibp_api: bool = False) -> dict:
    """
    Comprehensive password strength analysis.
    Returns a full analysis dict.
    """

    # Default policy
    if policy is None:
        policy = {
            "min_length":       8,
            "max_length":       128,
            "require_upper":    True,
            "require_lower":    True,
            "require_digit":    True,
            "require_special":  False,
            "min_unique_chars": 4,
        }

    result = {
        "password":         "*" * len(password),   # Never store plain text
        "length":           len(password),
        "entropy_bits":     0.0,
        "score":            0,           # 0-100
        "strength":         "",          # Very Weak / Weak / Fair / Strong / Very Strong
        "grade":            "",          # F / D / C / B / A / A+
        "checks":           {},
        "patterns":         [],
        "warnings":         [],
        "suggestions":      [],
        "crack_times":      {},
        "policy_pass":      False,
        "policy_failures":  [],
        "hibp":             {},
        "char_analysis":    {},
    }

    pw = password

    # ── CHARACTER SET ANALYSIS ──────────────────────────────
    has_lower   = bool(re.search(r'[a-z]', pw))
    has_upper   = bool(re.search(r'[A-Z]', pw))
    has_digit   = bool(re.search(r'[0-9]', pw))
    has_special = bool(re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?/\\`~"\']', pw))
    has_space   = " " in pw

    unique_chars = len(set(pw))
    char_freq    = {}
    for ch in pw:
        char_freq[ch] = char_freq.get(ch, 0) + 1

    result["char_analysis"] = {
        "has_lowercase":  has_lower,
        "has_uppercase":  has_upper,
        "has_digits":     has_digit,
        "has_special":    has_special,
        "has_space":      has_space,
        "unique_chars":   unique_chars,
        "length":         len(pw),
        "char_types":     sum([has_lower, has_upper, has_digit, has_special]),
    }

    # ── CHECKS ────────────────────────────────────────────────
    checks = {
        "length_8":         len(pw) >= 8,
        "length_12":        len(pw) >= 12,
        "length_16":        len(pw) >= 16,
        "has_lowercase":    has_lower,
        "has_uppercase":    has_upper,
        "has_digit":        has_digit,
        "has_special":      has_special,
        "has_4_char_types": sum([has_lower, has_upper, has_digit, has_special]) >= 4,
        "unique_4":         unique_chars >= 4,
        "unique_8":         unique_chars >= 8,
        "not_common":       pw.lower() not in COMMON_PASSWORDS,
        "no_repeated_chars": not bool(re.search(r'(.)\1{2,}', pw)),
        "no_sequential":    True,   # Updated below
        "not_keyboard":     True,   # Updated below
    }

    # ── PATTERN DETECTION ─────────────────────────────────────
    patterns_found = []

    # 1. Common password check
    if pw.lower() in COMMON_PASSWORDS:
        patterns_found.append("Common/dictionary password")
        result["warnings"].append("This password appears in common password lists")

    # 2. Leet speak check (convert leet → normal and check again)
    leet_converted = pw.lower()
    for leet, normal in LEET_MAP.items():
        leet_converted = leet_converted.replace(leet, normal)
    if leet_converted in COMMON_PASSWORDS:
        patterns_found.append("Leet-speak variation of common password")
        result["warnings"].append("Leet-speak substitutions (@ for a, 3 for e) are easily cracked")

    # 3. Sequential characters
    seq_found = False
    for i in range(len(pw) - 2):
        a, b, c = ord(pw[i]), ord(pw[i+1]), ord(pw[i+2])
        if (b - a == 1) and (c - b == 1):
            seq_found = True
            break
        if (a - b == 1) and (b - c == 1):
            seq_found = True
            break
    if seq_found:
        patterns_found.append("Sequential characters (abc, 123)")
        checks["no_sequential"] = False

    # 4. Keyboard walk patterns
    pw_lower = pw.lower()
    for pattern in KEYBOARD_PATTERNS:
        if pattern in pw_lower or pattern[::-1] in pw_lower:
            patterns_found.append(f"Keyboard walk pattern detected")
            checks["not_keyboard"] = False
            break

    # 5. Repeated characters
    if re.search(r'(.)\1{2,}', pw):
        patterns_found.append("Repeated characters (aaa, 111)")

    # 6. All same character type
    if pw.isdigit():
        patterns_found.append("All digits — no letters")
    elif pw.isalpha():
        patterns_found.append("All letters — no numbers or symbols")
    elif pw.islower():
        patterns_found.append("All lowercase — no uppercase")
    elif pw.isupper():
        patterns_found.append("All uppercase — no lowercase")

    # 7. Number/symbol only at start or end
    if re.match(r'^[A-Za-z]+[0-9]+$', pw):
        patterns_found.append("Numbers only at end (wordNUM pattern — common)")
    if re.match(r'^[A-Za-z]+[^A-Za-z0-9]$', pw):
        patterns_found.append("Special char only at end (word! pattern — common)")

    # 8. Year patterns
    if re.search(r'(19|20)\d{2}', pw):
        patterns_found.append("Contains a year (19xx or 20xx)")

    # 9. Date patterns
    if re.search(r'\d{1,2}[\/\-\.]\d{1,2}([\/\-\.]\d{2,4})?', pw):
        patterns_found.append("Contains a date pattern")

    # 10. Phone number patterns
    if re.search(r'0\d{9}|\d{10}', pw):
        patterns_found.append("May contain a phone number pattern")

    result["patterns"] = patterns_found

    # ── ENTROPY ────────────────────────────────────────────────
    entropy = calculate_entropy(pw)
    result["entropy_bits"] = round(entropy, 2)

    # ── SCORING ────────────────────────────────────────────────
    score = 0

    # Length scoring (max 30 points)
    length = len(pw)
    if length >= 20:    score += 30
    elif length >= 16:  score += 25
    elif length >= 12:  score += 20
    elif length >= 10:  score += 15
    elif length >= 8:   score += 10
    else:               score += length  # 1 point per char under 8

    # Character variety (max 30 points)
    variety = sum([has_lower, has_upper, has_digit, has_special])
    score += variety * 7  # 7 points per character type (max 28)
    if has_space:
        score += 5  # Bonus for passphrase-style spaces

    # Uniqueness (max 15 points)
    if unique_chars >= 15:   score += 15
    elif unique_chars >= 10: score += 12
    elif unique_chars >= 8:  score += 9
    elif unique_chars >= 6:  score += 6
    elif unique_chars >= 4:  score += 3

    # Entropy bonus (max 10 points)
    if entropy >= 70:        score += 10
    elif entropy >= 60:      score += 8
    elif entropy >= 50:      score += 6
    elif entropy >= 40:      score += 4
    elif entropy >= 30:      score += 2

    # Deductions
    if pw.lower() in COMMON_PASSWORDS:          score -= 40
    if leet_converted in COMMON_PASSWORDS:      score -= 20
    if not checks["no_sequential"]:             score -= 10
    if not checks["not_keyboard"]:              score -= 10
    if not checks["no_repeated_chars"]:         score -= 8
    if re.match(r'^[A-Za-z]+[0-9]+$', pw):     score -= 5
    if length < 8:                              score -= 15

    score = max(0, min(100, score))
    result["score"] = score

    # ── STRENGTH LABEL ─────────────────────────────────────────
    if score >= 90:
        result["strength"] = "Very Strong"
        result["grade"]    = "A+"
    elif score >= 75:
        result["strength"] = "Strong"
        result["grade"]    = "A"
    elif score >= 60:
        result["strength"] = "Good"
        result["grade"]    = "B"
    elif score >= 45:
        result["strength"] = "Fair"
        result["grade"]    = "C"
    elif score >= 30:
        result["strength"] = "Weak"
        result["grade"]    = "D"
    else:
        result["strength"] = "Very Weak"
        result["grade"]    = "F"

    # ── CHECKS RESULT ──────────────────────────────────────────
    result["checks"] = checks

    # ── CRACK TIMES ────────────────────────────────────────────
    result["crack_times"] = estimate_crack_time(entropy)

    # ── POLICY CHECK ───────────────────────────────────────────
    policy_failures = []

    if len(pw) < policy["min_length"]:
        policy_failures.append(f"Too short: {len(pw)} chars (minimum {policy['min_length']})")
    if len(pw) > policy["max_length"]:
        policy_failures.append(f"Too long: {len(pw)} chars (maximum {policy['max_length']})")
    if policy["require_upper"] and not has_upper:
        policy_failures.append("Missing uppercase letter (A-Z)")
    if policy["require_lower"] and not has_lower:
        policy_failures.append("Missing lowercase letter (a-z)")
    if policy["require_digit"] and not has_digit:
        policy_failures.append("Missing digit (0-9)")
    if policy["require_special"] and not has_special:
        policy_failures.append("Missing special character (!@#$...)")
    if unique_chars < policy["min_unique_chars"]:
        policy_failures.append(f"Too few unique characters: {unique_chars} (minimum {policy['min_unique_chars']})")

    result["policy_failures"] = policy_failures
    result["policy_pass"]     = len(policy_failures) == 0

    # ── SUGGESTIONS ────────────────────────────────────────────
    suggestions = []

    if length < 12:
        suggestions.append("Use at least 12 characters — length is the most important factor")
    if not has_upper and not has_lower:
        suggestions.append("Mix uppercase and lowercase letters")
    elif not has_upper:
        suggestions.append("Add uppercase letters (A-Z)")
    elif not has_lower:
        suggestions.append("Add lowercase letters (a-z)")
    if not has_digit:
        suggestions.append("Include numbers (0-9)")
    if not has_special:
        suggestions.append("Add special characters (!@#$%^&*)")
    if unique_chars < 8:
        suggestions.append("Use more unique characters — avoid repeating the same characters")
    if pw.lower() in COMMON_PASSWORDS or leet_converted in COMMON_PASSWORDS:
        suggestions.append("This password is in common dictionaries — choose something unique")
    if not checks["no_sequential"]:
        suggestions.append("Avoid sequential characters (abc, 123, xyz)")
    if not checks["not_keyboard"]:
        suggestions.append("Avoid keyboard walk patterns (qwerty, asdf)")
    if re.match(r'^[A-Za-z]+[0-9]+$', pw):
        suggestions.append("Avoid the pattern: word + numbers (e.g. password123)")
    if length >= 12 and variety >= 3 and score >= 60:
        suggestions.append("Consider using a passphrase: 4-5 random words separated by symbols")

    if not suggestions and score >= 75:
        suggestions.append("Excellent password! Store it securely in a password manager.")

    result["suggestions"] = suggestions

    # ── HIBP CHECK ─────────────────────────────────────────────
    if check_hibp_api:
        result["hibp"] = check_hibp(pw)

    return result


# ─────────────────────────────────────────────────────────────
# PASSWORD GENERATOR
# ─────────────────────────────────────────────────────────────

def generate_password(length: int = 16, style: str = "mixed") -> str:
    """
    Generate a cryptographically secure password.
    Styles: mixed, passphrase, memorable
    """
    if style == "passphrase":
        # Passphrase: 4-6 random words from a small vocabulary
        words = [
            "apple", "brave", "cloud", "dance", "eagle", "flame",
            "grove", "house", "ivory", "jumbo", "knife", "lemon",
            "maple", "night", "ocean", "piano", "queen", "river",
            "stone", "tiger", "ultra", "vivid", "water", "xenon",
            "yacht", "zebra", "amber", "blaze", "coral", "drift",
            "ember", "frost", "glare", "haven", "iris", "joker",
            "karma", "lunar", "magic", "noble", "onyx", "prism",
            "quest", "robin", "solar", "tower", "union", "valor",
            "witch", "xylem", "youth", "zonal", "azure", "bloom",
        ]
        num_words = max(4, length // 5)
        chosen = [secrets.choice(words) for _ in range(num_words)]
        separators = [".", "-", "_", "!", "@", "#"]
        sep = secrets.choice(separators)
        # Add a random number for extra entropy
        number = str(secrets.randbelow(999))
        phrase = sep.join(chosen) + sep + number
        return phrase

    elif style == "memorable":
        # Memorable: consonant-vowel pairs (pronounceable)
        consonants = "bcdfghjklmnprstvwyz"
        vowels     = "aeiou"
        digits     = "0123456789"
        special    = "!@#$%"

        result = ""
        for i in range(length // 2):
            result += secrets.choice(consonants.upper() if i == 0 else consonants)
            result += secrets.choice(vowels)
        result += secrets.choice(digits)
        result += secrets.choice(digits)
        result += secrets.choice(special)
        return result[:length]

    else:  # "mixed" — default
        charset = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"

        while True:
            pwd = "".join(secrets.choice(charset) for _ in range(length))
            # Ensure all character types are present
            if (re.search(r'[a-z]', pwd) and
                re.search(r'[A-Z]', pwd) and
                re.search(r'[0-9]', pwd) and
                re.search(r'[!@#$%^&*()\-_=+]', pwd)):
                return pwd


# ─────────────────────────────────────────────────────────────
# DISPLAY FUNCTIONS
# ─────────────────────────────────────────────────────────────

def print_banner():
    print(f"""
{Colour.CYAN}{Colour.BOLD}
╔══════════════════════════════════════════════════════════════╗
║         PASSWORD STRENGTH CHECKER  v1.0                      ║
║         Security Analysis & Policy Enforcement Tool          ║
║                                                              ║
║  Author  : Rishabh Sankhla  |  CEH v13  |  TryHackMe Top 2% ║
╚══════════════════════════════════════════════════════════════╝
{Colour.RESET}""")


def score_bar(score: int, width: int = 30) -> str:
    """Create a visual score bar."""
    filled = int((score / 100) * width)
    empty  = width - filled

    if score >= 75:
        col = Colour.GREEN
    elif score >= 50:
        col = Colour.YELLOW
    else:
        col = Colour.RED

    bar = f"{col}{'█' * filled}{Colour.DIM}{'░' * empty}{Colour.RESET}"
    return f"[{bar}] {Colour.BOLD}{score}/100{Colour.RESET}"


def strength_colour(strength: str) -> str:
    """Colour-code a strength label."""
    colours = {
        "Very Strong": Colour.GREEN  + Colour.BOLD,
        "Strong":      Colour.GREEN,
        "Good":        Colour.CYAN,
        "Fair":        Colour.YELLOW,
        "Weak":        Colour.RED,
        "Very Weak":   Colour.RED    + Colour.BOLD,
    }
    return colours.get(strength, "") + strength + Colour.RESET


def grade_colour(grade: str) -> str:
    """Colour-code a grade."""
    colours = {
        "A+": Colour.GREEN  + Colour.BOLD,
        "A":  Colour.GREEN,
        "B":  Colour.CYAN,
        "C":  Colour.YELLOW,
        "D":  Colour.RED,
        "F":  Colour.RED    + Colour.BOLD,
    }
    return colours.get(grade, "") + grade + Colour.RESET


def print_analysis(result: dict, show_crack_times: bool = True,
                   show_hibp: bool = False, password_label: str = ""):
    """Print a full password analysis report."""

    label = f"  [{password_label}]" if password_label else ""
    print(f"\n{Colour.CYAN}{Colour.BOLD}{'═'*60}{Colour.RESET}")
    print(f"{Colour.BOLD}  PASSWORD ANALYSIS{label}{Colour.RESET}")
    print(f"{'─'*60}")

    # Masked password display
    pw_masked = result["password"]
    print(f"  Password : {Colour.WHITE}{pw_masked}{Colour.RESET}  ({result['length']} characters)")

    # Score bar
    print(f"  Score    : {score_bar(result['score'])}")

    # Strength and grade
    print(f"  Strength : {strength_colour(result['strength'])}  "
          f"Grade: {grade_colour(result['grade'])}")

    # Entropy
    entropy = result["entropy_bits"]
    if entropy >= 70:
        e_col = Colour.GREEN
    elif entropy >= 50:
        e_col = Colour.YELLOW
    else:
        e_col = Colour.RED
    print(f"  Entropy  : {e_col}{entropy} bits{Colour.RESET}")

    # ── CHARACTER ANALYSIS ─────────────────────────────────────
    print(f"\n{Colour.BOLD}  Character Analysis:{Colour.RESET}")
    ca = result["char_analysis"]

    checks_display = [
        (ca["has_lowercase"],  "Lowercase letters (a-z)"),
        (ca["has_uppercase"],  "Uppercase letters (A-Z)"),
        (ca["has_digits"],     "Digits (0-9)"),
        (ca["has_special"],    "Special characters (!@#...)"),
        (ca["length"] >= 8,    f"Length ≥ 8 ({ca['length']} chars)"),
        (ca["length"] >= 12,   f"Length ≥ 12 ({ca['length']} chars)"),
        (ca["unique_chars"] >= 8, f"8+ unique chars ({ca['unique_chars']} unique)"),
    ]

    for passed, label in checks_display:
        icon = f"{Colour.GREEN}✓{Colour.RESET}" if passed else f"{Colour.RED}✗{Colour.RESET}"
        print(f"    {icon}  {label}")

    # ── PATTERNS DETECTED ──────────────────────────────────────
    if result["patterns"]:
        print(f"\n{Colour.BOLD}  Patterns Detected:{Colour.RESET}")
        for pattern in result["patterns"]:
            print(f"    {Colour.YELLOW}⚠{Colour.RESET}  {pattern}")

    # ── POLICY CHECK ───────────────────────────────────────────
    print(f"\n{Colour.BOLD}  Policy Check:{Colour.RESET}", end="")
    if result["policy_pass"]:
        print(f"  {Colour.GREEN}✓ PASS{Colour.RESET}")
    else:
        print(f"  {Colour.RED}✗ FAIL{Colour.RESET}")
        for failure in result["policy_failures"]:
            print(f"    {Colour.RED}→{Colour.RESET}  {failure}")

    # ── CRACK TIMES ────────────────────────────────────────────
    if show_crack_times:
        print(f"\n{Colour.BOLD}  Estimated Crack Times:{Colour.RESET}")
        for scenario, data in result["crack_times"].items():
            label = data["label"]
            seconds = data["seconds"]

            if seconds < 3600:
                t_col = Colour.RED + Colour.BOLD
            elif seconds < 86400:
                t_col = Colour.RED
            elif seconds < 2_592_000:
                t_col = Colour.YELLOW
            elif seconds < 31_536_000:
                t_col = Colour.CYAN
            else:
                t_col = Colour.GREEN

            print(f"    {Colour.DIM}{scenario:<30}{Colour.RESET}: {t_col}{label}{Colour.RESET}")

    # ── HIBP CHECK ─────────────────────────────────────────────
    if show_hibp and result.get("hibp"):
        h = result["hibp"]
        print(f"\n{Colour.BOLD}  HaveIBeenPwned Check:{Colour.RESET}")
        if h.get("error"):
            print(f"    {Colour.YELLOW}⚠{Colour.RESET}  {h['error']}")
        elif h.get("checked"):
            if h.get("pwned"):
                count = h["count"]
                print(f"    {Colour.RED}{Colour.BOLD}✗ BREACHED!{Colour.RESET}  "
                      f"Found {Colour.RED}{count:,}{Colour.RESET} times in data breaches")
                print(f"    {Colour.RED}This password should NEVER be used!{Colour.RESET}")
            else:
                print(f"    {Colour.GREEN}✓ Not found{Colour.RESET}  Not in any known data breaches")
        else:
            print(f"    {Colour.DIM}Check skipped{Colour.RESET}")

    # ── WARNINGS ───────────────────────────────────────────────
    if result["warnings"]:
        print(f"\n{Colour.BOLD}  Warnings:{Colour.RESET}")
        for warning in result["warnings"]:
            print(f"    {Colour.RED}!{Colour.RESET}  {warning}")

    # ── SUGGESTIONS ────────────────────────────────────────────
    if result["suggestions"]:
        print(f"\n{Colour.BOLD}  Suggestions:{Colour.RESET}")
        for suggestion in result["suggestions"]:
            print(f"    {Colour.CYAN}→{Colour.RESET}  {suggestion}")

    print(f"{Colour.CYAN}{'═'*60}{Colour.RESET}")


def print_batch_summary(results: list):
    """Print summary for batch password checking."""
    total      = len(results)
    grades     = {"A+": 0, "A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    strengths  = {}
    policy_pass = 0
    avg_score  = 0
    breached   = 0

    for r in results:
        g = r.get("grade", "F")
        grades[g] = grades.get(g, 0) + 1
        s = r.get("strength", "Very Weak")
        strengths[s] = strengths.get(s, 0) + 1
        avg_score += r.get("score", 0)
        if r.get("policy_pass"):
            policy_pass += 1
        if r.get("hibp", {}).get("pwned"):
            breached += 1

    avg_score = avg_score / total if total else 0

    print(f"\n{Colour.CYAN}{Colour.BOLD}{'═'*60}{Colour.RESET}")
    print(f"{Colour.BOLD}  BATCH ANALYSIS SUMMARY ({total} passwords){Colour.RESET}")
    print(f"{'─'*60}")
    print(f"  Average Score  : {score_bar(int(avg_score), 20)}")
    print(f"  Policy Pass    : {Colour.GREEN}{policy_pass}{Colour.RESET} / {total} "
          f"({int(policy_pass/total*100)}%)")
    if breached > 0:
        print(f"  Breached (HIBP): {Colour.RED}{Colour.BOLD}{breached}{Colour.RESET}")

    print(f"\n  {Colour.BOLD}Grade Distribution:{Colour.RESET}")
    for grade, count in sorted(grades.items()):
        if count > 0:
            bar = "█" * count
            pct = int(count / total * 100)
            print(f"    {grade_colour(grade):<20} {bar} ({count}, {pct}%){Colour.RESET}")

    print(f"\n  {Colour.BOLD}Strength Distribution:{Colour.RESET}")
    for strength, count in sorted(strengths.items(), key=lambda x: -x[1]):
        bar = "█" * count
        pct = int(count / total * 100)
        print(f"    {strength_colour(strength):<25} {bar} ({count}, {pct}%){Colour.RESET}")

    print(f"{Colour.CYAN}{'═'*60}{Colour.RESET}\n")


# ─────────────────────────────────────────────────────────────
# SAVE REPORT
# ─────────────────────────────────────────────────────────────

def save_report(results: list, output_file: str):
    """Save analysis results to JSON (passwords masked)."""
    # Remove hibp raw data from output for privacy
    clean = []
    for r in results:
        c = dict(r)
        # Keep HIBP result but ensure password is masked
        c["password"] = r["password"]  # Already masked to *****
        clean.append(c)

    data = {
        "tool":      "password_strength.py by Rishabh Sankhla",
        "timestamp": datetime.now().isoformat(),
        "count":     len(results),
        "results":   clean,
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"{Colour.GREEN}[+] Report saved → {output_file}{Colour.RESET}")


# ─────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Password Strength Checker — Comprehensive security analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python3 password_strength.py
  python3 password_strength.py -p "MySecurePass123!"
  python3 password_strength.py -f passwords.txt --hibp
  python3 password_strength.py --generate --length 20
  python3 password_strength.py --generate --style passphrase
  python3 password_strength.py -p "test" --min-length 12 --require-special
  python3 password_strength.py -f company_passwords.txt --output audit.json

NOTE:
  Passwords passed via -p are visible in shell history.
  Use interactive mode (no flags) for secure input.
        """
    )

    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("-p", "--password",
                             help="Password to analyse (visible in shell history!)")
    input_group.add_argument("-f", "--file",
                             help="File with passwords to analyse (one per line)")
    input_group.add_argument("--generate", action="store_true",
                             help="Generate a strong password instead")

    parser.add_argument("--length",  type=int, default=16,
                        help="Generated password length (default: 16)")
    parser.add_argument("--style",
                        choices=["mixed", "passphrase", "memorable"],
                        default="mixed",
                        help="Generated password style (default: mixed)")
    parser.add_argument("--count",   type=int, default=1,
                        help="Number of passwords to generate (default: 1)")

    parser.add_argument("--hibp",    action="store_true",
                        help="Check against HaveIBeenPwned breach database (requires internet)")
    parser.add_argument("--no-crack-times", action="store_true",
                        help="Skip crack time estimation")
    parser.add_argument("--output",  help="Save report to JSON file")
    parser.add_argument("--no-colour", action="store_true",
                        help="Disable coloured output")

    # Custom policy options
    policy = parser.add_argument_group("Custom Policy")
    policy.add_argument("--min-length",    type=int, default=8)
    policy.add_argument("--max-length",    type=int, default=128)
    policy.add_argument("--require-upper",   action="store_true", default=True)
    policy.add_argument("--require-lower",   action="store_true", default=True)
    policy.add_argument("--require-digit",   action="store_true", default=True)
    policy.add_argument("--require-special", action="store_true", default=False)
    policy.add_argument("--min-unique",    type=int, default=4,
                        help="Minimum unique characters required")

    return parser.parse_args()


# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if args.no_colour or (os.name == "nt" and "ANSICON" not in os.environ):
        Colour.disable()

    print_banner()

    policy = {
        "min_length":       args.min_length,
        "max_length":       args.max_length,
        "require_upper":    args.require_upper,
        "require_lower":    args.require_lower,
        "require_digit":    args.require_digit,
        "require_special":  args.require_special,
        "min_unique_chars": args.min_unique,
    }

    show_crack = not args.no_crack_times

    # ── GENERATE MODE ─────────────────────────────────────────
    if args.generate:
        print(f"{Colour.CYAN}[*]{Colour.RESET} Generating {args.count} password(s) "
              f"(length={args.length}, style={args.style})\n")

        generated = []
        for i in range(args.count):
            pwd = generate_password(args.length, args.style)
            generated.append(pwd)
            result = analyse_password(pwd, policy)

            print(f"  {Colour.BOLD}{Colour.GREEN}Password {i+1}:{Colour.RESET}  "
                  f"{Colour.WHITE}{Colour.BOLD}{pwd}{Colour.RESET}")
            print(f"  Strength : {strength_colour(result['strength'])}  "
                  f"Score: {result['score']}/100  "
                  f"Entropy: {result['entropy_bits']} bits")
            print(f"  {Colour.DIM}(Copy and store in a password manager){Colour.RESET}\n")

        if args.count > 1:
            print(f"\n{Colour.CYAN}[*]{Colour.RESET} All {args.count} passwords generated above.")
        return

    # ── FILE MODE ─────────────────────────────────────────────
    if args.file:
        if not os.path.isfile(args.file):
            print(f"{Colour.RED}[!] File not found: {args.file}{Colour.RESET}")
            sys.exit(1)

        with open(args.file, encoding="utf-8", errors="replace") as f:
            passwords = [line.strip() for line in f
                         if line.strip() and not line.startswith("#")]

        if not passwords:
            print(f"{Colour.RED}[!] No passwords found in file.{Colour.RESET}")
            sys.exit(1)

        print(f"{Colour.CYAN}[*]{Colour.RESET} Analysing {len(passwords)} passwords from: {args.file}")
        if args.hibp:
            print(f"{Colour.YELLOW}[!]{Colour.RESET} HIBP check enabled — "
                  f"checking each password against breach database...")
        print()

        all_results = []
        for i, pwd in enumerate(passwords):
            result = analyse_password(pwd, policy, args.hibp)
            all_results.append(result)

            label = f"{i+1}/{len(passwords)}"
            # Brief output per password
            masked = "*" * min(len(pwd), 4) + "..." if len(pwd) > 4 else "*" * len(pwd)
            print(f"  [{label}] {masked:<20} "
                  f"Score: {result['score']:>3}/100  "
                  f"{strength_colour(result['strength']):<20}  "
                  f"Grade: {grade_colour(result['grade'])}", end="")

            if args.hibp and result.get("hibp", {}).get("pwned"):
                print(f"  {Colour.RED}⚠ BREACHED{Colour.RESET}", end="")
            print()

        print_batch_summary(all_results)

        if args.output:
            save_report(all_results, args.output)

        return

    # ── SINGLE PASSWORD MODE ───────────────────────────────────
    if args.password:
        pwd = args.password
        print(f"{Colour.YELLOW}[!]{Colour.RESET} Note: Password visible in shell history. "
              f"Use interactive mode for sensitive passwords.\n")
    else:
        # Interactive secure input
        print(f"{Colour.CYAN}[*]{Colour.RESET} Enter password for analysis "
              f"(input hidden):\n")
        try:
            pwd = getpass.getpass("  Password: ")
        except KeyboardInterrupt:
            print(f"\n{Colour.DIM}[Cancelled]{Colour.RESET}")
            sys.exit(0)

    if not pwd:
        print(f"{Colour.RED}[!] No password entered.{Colour.RESET}")
        sys.exit(1)

    if args.hibp:
        print(f"\n{Colour.CYAN}[*]{Colour.RESET} Checking HaveIBeenPwned API "
              f"(k-anonymity — your password is never sent)...")

    result = analyse_password(pwd, policy, args.hibp)
    print_analysis(result, show_crack, args.hibp)

    if args.output:
        save_report([result], args.output)


if __name__ == "__main__":
    main()
