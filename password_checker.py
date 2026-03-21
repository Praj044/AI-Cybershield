"""
password_checker.py
--------------------
Evaluates password strength using the zxcvbn library.
Returns a structured dict with score, crack time, and suggestions.
"""

from zxcvbn import zxcvbn

STRENGTH_LABELS = {
    0: ("Too Weak", "🔴"),
    1: ("Weak", "🟠"),
    2: ("Fair", "🟡"),
    3: ("Strong", "🟢"),
    4: ("Very Strong", "✅"),
}


def check_password_strength(password: str) -> dict:
    """
    Analyzes the given password using zxcvbn.

    Args:
        password (str): The password string to evaluate.

    Returns:
        dict: {
            "score": int (0-4),
            "label": str,
            "emoji": str,
            "crack_time": str,
            "suggestions": list[str],
            "warning": str,
        }
    """
    if not password:
        return {
            "score": 0,
            "label": "No Input",
            "emoji": "⚪",
            "crack_time": "N/A",
            "suggestions": [],
            "warning": "Please enter a password.",
        }

    result = zxcvbn(password)
    score = result["score"]
    label, emoji = STRENGTH_LABELS[score]
    crack_time = result["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
    feedback = result.get("feedback", {})
    suggestions = feedback.get("suggestions", [])
    warning = feedback.get("warning", "")

    return {
        "score": score,
        "label": label,
        "emoji": emoji,
        "crack_time": crack_time,
        "suggestions": suggestions,
        "warning": warning,
    }


def get_score_deduction(password_result: dict) -> int:
    """
    Returns the security score deduction based on password strength.

    Args:
        password_result (dict): Output from check_password_strength.

    Returns:
        int: Points to deduct from the overall security score.
    """
    score = password_result.get("score", 0)
    deduction_map = {0: 40, 1: 30, 2: 15, 3: 5, 4: 0}
    return deduction_map.get(score, 0)


def generate_strong_password(count: int = 3) -> list[str]:
    """
    Generates strong password suggestions using Python's secrets module.

    Returns a list of ``count`` password strings, each using a different
    strategy so the user can pick the style they prefer:

      1. Random character mix  — hard to crack, good for password managers
      2. Passphrase-style       — 4 random words joined by symbols + digits
      3. Compact random         — shorter but still high-entropy

    Args:
        count (int): Number of suggestions to return (default 3).

    Returns:
        list[str]: List of strong password strings.
    """
    import secrets
    import string

    # Short word list for human-readable passphrases
    _WORDS = [
        "maple", "tiger", "frost", "orbit", "river", "flame", "storm", "pixel",
        "solar", "blade", "cloud", "swift", "raven", "forge", "amber", "crane",
        "delta", "ember", "fauna", "ghost", "ivory", "jade",  "kappa", "lunar",
        "mango", "nexus", "onyx",  "prism", "quartz","ridge", "sigma", "thorn",
        "ultra", "viper", "waltz", "xenon", "yield", "zephyr","brisk", "cobalt",
        "dusk",  "echo",  "flint", "gale",  "haven", "iron",  "joule", "knoll",
    ]

    all_chars   = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    upper_chars = string.ascii_uppercase
    lower_chars = string.ascii_lowercase
    digit_chars = string.digits
    sym_chars   = "!@#$%^&*-_=+"

    suggestions = []

    # --- Strategy 1: high-entropy random mix (16 chars) ----------------------
    def _random_mix(length=16):
        must_have = [
            secrets.choice(upper_chars),
            secrets.choice(lower_chars),
            secrets.choice(digit_chars),
            secrets.choice(sym_chars),
        ]
        rest = [secrets.choice(all_chars) for _ in range(length - 4)]
        pool = must_have + rest
        secrets.SystemRandom().shuffle(pool)
        return "".join(pool)

    # --- Strategy 2: passphrase (4 words + digits + symbol) ------------------
    def _passphrase():
        words = [secrets.choice(_WORDS).capitalize() for _ in range(4)]
        num   = secrets.randbelow(900) + 100          # 3-digit number
        sym   = secrets.choice(sym_chars)
        return f"{words[0]}{words[1]}{sym}{words[2]}{words[3]}{num}"

    # --- Strategy 3: compact random (14 chars) --------------------------------
    def _compact(length=14):
        must_have = [
            secrets.choice(upper_chars),
            secrets.choice(lower_chars),
            secrets.choice(digit_chars),
            secrets.choice(sym_chars),
        ]
        rest = [secrets.choice(all_chars) for _ in range(length - 4)]
        pool = must_have + rest
        secrets.SystemRandom().shuffle(pool)
        return "".join(pool)

    strategies = [_random_mix, _passphrase, _compact]
    for i in range(count):
        suggestions.append(strategies[i % len(strategies)]())

    return suggestions

