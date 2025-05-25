from django.core.exceptions import ValidationError
import re

class PatternPasswordValidator:
    """
    Validate that the password is not using common predictable patterns.
    """
    
    def __init__(self):
        self.keyboard_patterns = [
            'qwert', 'asdfg', 'zxcvb', 'yuiop', 'hjkl', 'nm',  # horizontal patterns
            'qaz', 'wsx', 'edc', 'rfv', 'tgb', 'yhn', 'ujm', 'ik', 'ol', 'p',  # vertical patterns
            '1234', '2345', '3456', '4567', '5678', '6789', '7890',  # numerical sequences
            'abcd', 'bcde', 'cdef', 'defg', 'efgh', 'fghi', 'ghij', 'hijk',  # alphabet sequences
            'ijkl', 'jklm', 'klmn', 'lmno', 'mnop', 'nopq', 'opqr', 'pqrs', 
            'qrst', 'rstu', 'stuv', 'tuvw', 'uvwx', 'vwxy', 'wxyz',
            'qwerty', 'asdf', 'zxcv'  # common full sequences
        ]
        
        self.common_patterns = [
            r'^[a-zA-Z]+[0-9]{1,4}$',  # letters followed by 1-4 digits
            r'^[a-zA-Z]+[@#$%^&*()!]{1}[0-9]{1,4}$',  # letters followed by a special char and 1-4 digits
            r'^[A-Z][a-z]+[0-9]{1,4}$',  # Capital letter, lowercase letters, 1-4 digits
            r'^[A-Z][a-z]+[@#$%^&*()!]{1}[0-9]{1,4}$',  # Capital letter, lowercase letters, special char, 1-4 digits
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{1,8}$',  # Simple complexity pattern with short length
        ]
        
        self.common_words = [
            'password', 'admin', 'welcome', 'login', 'user', 'test', 'secure', 'qwerty', 'letmein',
            'asdf', 'hello', 'abc123', 'monkey', 'dragon', 'master', 'football', 'baseball', 'superman',
            'batman', 'trustno1', 'sunshine', 'iloveyou', 'princess', 'starwars', 'whatever'
        ]
        
    def validate(self, password, user=None):
        # Check for keyboard patterns
        password_lower = password.lower()
        
        # Strip special characters and digits for pattern checking
        # This helps catch patterns like QwErTy@12 or P@ssw0rd
        password_stripped = re.sub(r'[^a-z]', '', password_lower)
        
        # Check original lowercase password for patterns
        for pattern in self.keyboard_patterns:
            if pattern in password_lower:
                raise ValidationError(
                    f"Password contains a common keyboard pattern '{pattern}'.",
                    code='password_keyboard_pattern',
                )
        
        # Check stripped password for patterns (to catch passwords with inserted symbols/numbers)
        for pattern in self.keyboard_patterns:
            if len(pattern) >= 4 and pattern in password_stripped:
                raise ValidationError(
                    f"Password contains a common keyboard pattern with symbols/numbers inserted.",
                    code='password_keyboard_pattern',
                )
        
        # Check for common patterns using regex
        for pattern in self.common_patterns:
            if re.match(pattern, password):
                raise ValidationError(
                    "Password follows a common guessable pattern. Please use a more unique combination.",
                    code='password_common_pattern',
                )
        
        # Check for common words
        for word in self.common_words:
            if word in password_lower:
                raise ValidationError(
                    f"Password contains a common word '{word}'.",
                    code='password_common_word',
                )
        
        # Check for simple letters+numbers combinations
        if (re.match(r'^[A-Z][a-z]+\d{2}$', password) or  # Like "Admin12"
            re.match(r'^[A-Z][a-z]+[@#$]\d{2}$', password)):  # Like "Admin@12"
            raise ValidationError(
                "Password follows a predictable pattern (like 'Password123' or 'Admin@12'). Please use a more unique combination.",
                code='password_predictable_pattern',
            )
            
        # Check for l33t speak substitutions (like p@ssw0rd, qw3rty)
        leet_pattern = re.sub(r'[0@$4!1]', lambda m: {'0':'o', '@':'a', '$':'s', '4':'a', '!':'i', '1':'i'}[m.group(0)], password_lower)
        
        for pattern in self.keyboard_patterns:
            if len(pattern) >= 4 and pattern in leet_pattern:
                raise ValidationError(
                    "Password uses l33t speak substitutions of a common pattern.",
                    code='password_leet_pattern',
                )
                
        for word in self.common_words:
            if word in leet_pattern:
                raise ValidationError(
                    "Password uses l33t speak substitutions of a common word.",
                    code='password_leet_word',
                )
        
        # Detect alternating case patterns (like QwErTy)
        if len(password) >= 6:
            stripped_chars = [c for c in password if c.isalpha()]
            if len(stripped_chars) >= 6:
                alternating = True
                for i in range(2, len(stripped_chars)):
                    # Check if the case pattern alternates (uppercase, lowercase, uppercase, etc.)
                    if (stripped_chars[i].isupper() == stripped_chars[i-2].isupper() and
                        stripped_chars[i-1].isupper() != stripped_chars[i].isupper()):
                        continue
                    else:
                        alternating = False
                        break
                
                if alternating:
                    # Now check if the lowercase version forms a common pattern
                    lowercase_str = ''.join(c.lower() for c in stripped_chars)
                    for pattern in self.keyboard_patterns:
                        if len(pattern) >= 4 and pattern in lowercase_str:
                            raise ValidationError(
                                "Password uses alternating case in a common pattern.",
                                code='password_alternating_case_pattern',
                            )
    
    def get_help_text(self):
        return "Your password must not use common patterns like keyboard sequences or predictable formats like 'Password123'." 