import re
from password_strength import PasswordPolicy
import zxcvbn

# 1. Regex based strength check
# -------------------------
def regex_strength(password: str) -> str:
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is None

    # Combine results
    errors = [length_error, digit_error, uppercase_error, lowercase_error, symbol_error]
    passed = errors.count(False)

    if passed == 5:
        return "Strong ✅"
    elif passed >= 3:
        return "Medium ⚠️"
    else:
        return "Weak ❌"


# 2. password_strength library (policy-based)
# -------------------------
policy = PasswordPolicy.from_names(
    length=8,     # minimum length: 8
    uppercase=1,  # need min. 1 uppercase letter
    numbers=1,    # need min. 1 digit
    special=1,    # need min. 1 special character
    nonletters=1, # need min. 1 non-letter
)

def policy_strength(password: str) -> str:
    test = policy.test(password)
    if not test:
        return "Strong ✅"
    else:
        return f"Weak ❌ (failed rules: {test})"


# 3. zxcvbn strength estimation
# -------------------------
def zxcvbn_strength(password: str) -> str:
    result = zxcvbn.zxcvbn(password)
    score = result["score"]  # 0 (very weak) → 4 (very strong)
    feedback = result["feedback"]

    levels = ["Very Weak ❌", "Weak ❌", "Fair ⚠️", "Good ✅", "Strong ✅"]
    return f"{levels[score]} | Suggestions: {feedback}"

# Main program
# -------------------------
if __name__ == "__main__":
    print("🔐 Password Strength Checker")
    print("Type 'exit' or 'quit' to stop.\n")

    while True:
        password = input("Enter your password:")

        if password.lower() in ["exit", "quit"]:
            print("👋 Exiting Password Checker. Stay secure!")
            break

        print("\n🔹 Regex Check:")
        print(regex_strength(password))

        print("\n🔹 Policy Check (password_strength):")
        print(policy_strength(password))

        print("\n🔹 ZXCVBN Check:")
        print(zxcvbn_strength(password))
        print("\n" + "-"*40 + "\n")

