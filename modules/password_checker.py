import math
import re

def check_password_strength(password):
    """
    Analyzes a password's strength based on specific criteria,
    calculates Shannon entropy, and returns a comprehensive report.
    """
    if not password:
        return None

    # 1. Initialize Criteria Checks
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digits = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^A-Za-z0-9]', password))

    # 2. Character Pool Size (R) for Entropy Calculation
    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digits: pool_size += 10
    if has_special: pool_size += 32  # Standard special characters estimate

    # Calculate Entropy: E = L * log2(R)
    entropy = 0
    if pool_size > 0:
        entropy = length * math.log2(pool_size)

    # 3. Strength Scoring (0 to 5 scale)
    score = 0
    feedback = []

    # Length Check
    if length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        feedback.append("❌ Password is too short (Minimum 8 characters, 12+ recommended).")

    # Character Variety Checks
    if has_upper: score += 1
    else: feedback.append("💡 Add uppercase letters (A-Z).")

    if has_lower: score += 1
    else: feedback.append("💡 Add lowercase letters (a-z).")

    if has_digits: score += 1
    else: feedback.append("💡 Add numbers (0-9).")

    if has_special: score += 1
    else: feedback.append("💡 Add special characters (e.g., !, @, #, $, %).")

    # Normalize score out of 5 max points
    score = min(score, 5)

    # 4. Categorization based on score and entropy
    if score <= 2 or entropy < 40:
        category = "Weak"
        color = "red"
    elif score <= 4 or entropy < 60:
        category = "Medium"
        color = "orange"
    else:
        category = "Strong"
        color = "green"

    if not feedback:
        feedback.append("✨ Excellent! Your password follows best security practices.")

    return {
        "length": length,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digits": has_digits,
        "has_special": has_special,
        "entropy": round(entropy, 2),
        "score": score,
        "category": category,
        "color": color,
        "feedback": feedback
    }