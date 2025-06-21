import re
from getpass import getpass
from typing import Dict, List, Tuple
from enum import Enum, auto
class PasswordStrength(Enum):
    VERY_WEAK = auto()
    WEAK = auto()
    MODERATE = auto()
    STRONG = auto()
    VERY_STRONG = auto()
class PasswordChecker:
    def __init__(self):
        self.min_length = 8
        self.requirements = {
            'length': lambda p: len(p) >= self.min_length,
            'lowercase': lambda p: bool(re.search(r'[a-z]', p)),
            'uppercase': lambda p: bool(re.search(r'[A-Z]', p)),
            'digit': lambda p: bool(re.search(r'[0-9]', p)),
            'special': lambda p: bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', p))
        }
        self.strength_thresholds = {
            PasswordStrength.VERY_WEAK: 0,
            PasswordStrength.WEAK: 1,
            PasswordStrength.MODERATE: 2,
            PasswordStrength.STRONG: 3,
            PasswordStrength.VERY_STRONG: 4
        }
    
    def analyze_password(self, password: str) -> Dict[str, bool]:
        """Analyze password against all requirements"""
        return {name: check(password) for name, check in self.requirements.items()}
    
    def calculate_strength(self, analysis: Dict[str, bool]) -> PasswordStrength:
        """Determine password strength based on met requirements"""
        met = sum(analysis.values())
        for strength, threshold in sorted(self.strength_thresholds.items(), key=lambda x: x[1], reverse=True):
            if met >= threshold:
                return strength
        return PasswordStrength.VERY_WEAK
    
    def get_feedback(self, analysis: Dict[str, bool], strength: PasswordStrength) -> Tuple[str, List[str]]:
        """Generate feedback based on password analysis"""
        strength_names = {
            PasswordStrength.VERY_WEAK: "Very Weak",
            PasswordStrength.WEAK: "Weak",
            PasswordStrength.MODERATE: "Moderate",
            PasswordStrength.STRONG: "Strong",
            PasswordStrength.VERY_STRONG: "Very Strong"
        }
        
        feedback = []
        unmet = [req for req, met in analysis.items() if not met]
        
        if strength in [PasswordStrength.VERY_WEAK, PasswordStrength.WEAK]:
            feedback.append("Your password is too easy to guess.")
        if 'length' in unmet:
            feedback.append(f"Add at least {self.min_length - len(password)} more characters.")
        if 'lowercase' in unmet:
            feedback.append("Add lowercase letters.")
        if 'uppercase' in unmet:
            feedback.append("Add uppercase letters.")
        if 'digit' in unmet:
            feedback.append("Add numbers.")
        if 'special' in unmet:
            feedback.append("Add special characters (!@#$%^&*).")
        
        if not feedback:
            feedback.append("Great password! Consider making it longer for extra security.")
        
        return strength_names[strength], feedback
    
    def display_results(self, password: str):
        """Display password analysis results"""
        print("\n" + "="*40)
        print("Password Strength Analysis")
        print("="*40)
        
        analysis = self.analyze_password(password)
        strength = self.calculate_strength(analysis)
        strength_name, feedback = self.get_feedback(analysis, strength)
        
        print(f"\nPassword: {'*' * len(password)}")
        print(f"Length: {len(password)} characters")
        print("\nRequirements met:")
        for req, met in analysis.items():
            print(f"- {req.capitalize()}: {'✓' if met else '✗'}")
        
        print(f"\nStrength: {strength_name}")
        print("\nRecommendations:")
        for item in feedback:
            print(f"- {item}")
        
        print("\n" + "="*40)

def get_password_input() -> str:
    """Securely get password input from user"""
    while True:
        password = getpass("Enter your password (or 'quit' to exit): ")
        if password.lower() == 'quit':
            return None
        if not password:
            print("Please enter a password.")
            continue
        return password

def main():
    print("Password Complexity Checker")
    print("--------------------------")
    print("This tool analyzes your password strength based on:")
    print("- Length (minimum 8 characters)")
    print("- Contains lowercase letters")
    print("- Contains uppercase letters")
    print("- Contains numbers")
    print("- Contains special characters")
    print("\nType 'quit' to exit at any time.\n")
    
    checker = PasswordChecker()
    
    while True:
        password = get_password_input()
        if password is None:
            break
        
        checker.display_results(password)

if __name__ == "__main__":
    main()
