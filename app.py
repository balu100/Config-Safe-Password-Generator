import secrets
import string
import random # Only needed for shuffling the final list
import math # For entropy calculation (optional, but used in new HTML)
from flask import Flask, render_template, request, flash

# --- Initialize Flask App ---
app = Flask(__name__)
# It's good practice to set a secret key for session management & flash messages
app.secret_key = secrets.token_hex(16)

# --- Character Definitions ---
SAFE_LOWER = string.ascii_lowercase
SAFE_UPPER = string.ascii_uppercase
SAFE_DIGITS = string.digits
DEFAULT_SAFE_SPECIAL = "_+.,?/@" # Default subset considered safer

# --- Detailed Special Character Information (for UI) ---
# Levels: 0=Very Low, 1=Low, 2=Medium, 3=High, 4=Very High
SPECIAL_CHARACTER_INFO = [
    # --- Level 0: Very Low Risk ---
    {'char': '_', 'risk_level': 0, 'risk': 'Very Low', 'reason': 'Standard identifier part, generally safe.'},

    # --- Level 1: Low Risk ---
    {'char': '@', 'risk_level': 1, 'risk': 'Low', 'reason': 'User/host separator, usually safe when quoted.'},
    {'char': '.', 'risk_level': 1, 'risk': 'Low', 'reason': 'Regex wildcard, path separator, usually safe quoted.'},
    {'char': ',', 'risk_level': 1, 'risk': 'Low', 'reason': 'List separator (flow), safe quoted.'},
    {'char': '+', 'risk_level': 1, 'risk': 'Low', 'reason': 'Regex operator, URL encoding, usually safe in values.'},
    {'char': '?', 'risk_level': 1, 'risk': 'Low', 'reason': 'Shell globbing (single char), safe when quoted.'},
    {'char': '/', 'risk_level': 1, 'risk': 'Low', 'reason': 'Path separator, generally safe within values.'},

    # --- Level 2: Medium Risk ---
    {'char': '-', 'risk_level': 2, 'risk': 'Medium', 'reason': 'Starts command-line options, ambiguous unquoted YAML.'},
    {'char': '=', 'risk_level': 2, 'risk': 'Medium', 'reason': 'Key/value separator (INI, TOML, env). Needs quoting.'},
    {'char': '%', 'risk_level': 2, 'risk': 'Medium', 'reason': 'Variable expansion (Win CMD), URL encoding, operators.'},
    {'char': '^', 'risk_level': 2, 'risk': 'Medium', 'reason': 'Special meaning (Win CMD escape, regex start).'},
    {'char': '~', 'risk_level': 2, 'risk': 'Medium', 'reason': 'Shell home expansion (unquoted start).'},
    {'char': ':', 'risk_level': 2, 'risk': 'Medium', 'reason': 'Key/value separator (YAML). Usually needs quoting.'},
    {'char': '€', 'risk_level': 2, 'risk': 'Medium', 'reason': 'Non-ASCII, potential encoding/font issues.'}, # Example Non-ASCII

    # --- Level 3: High Risk ---
    {'char': '#', 'risk_level': 3, 'risk': 'High', 'reason': 'Comment character (many formats). Needs quoting.'},
    {'char': ';', 'risk_level': 3, 'risk': 'High', 'reason': 'Shell command separator, INI comment. Needs quoting.'},
    {'char': '$', 'risk_level': 3, 'risk': 'High', 'reason': 'Shell variable expansion, regex end. Needs quoting.'},
    {'char': '!', 'risk_level': 3, 'risk': 'High', 'reason': 'Shell history expansion, logical NOT. Needs quoting.'},
    {'char': '*', 'risk_level': 3, 'risk': 'High', 'reason': 'Shell wildcard, regex quantifier. Needs quoting.'},
    {'char': '(', 'risk_level': 3, 'risk': 'High', 'reason': 'Shell subshell/grouping. Needs quoting.'},
    {'char': ')', 'risk_level': 3, 'risk': 'High', 'reason': 'Shell subshell/grouping. Needs quoting.'},
    {'char': '[', 'risk_level': 3, 'risk': 'High', 'reason': 'Syntax (lists/tables), shell globbing. Needs quoting.'},
    {'char': ']', 'risk_level': 3, 'risk': 'High', 'reason': 'Syntax (lists/tables), shell globbing. Needs quoting.'},
    {'char': '{', 'risk_level': 3, 'risk': 'High', 'reason': 'Syntax (maps), shell expansion. Needs quoting.'},
    {'char': '}', 'risk_level': 3, 'risk': 'High', 'reason': 'Syntax (maps), shell expansion. Needs quoting.'},
    {'char': "'", 'risk_level': 3, 'risk': 'High', 'reason': 'String quoting character. Breaks simple quoting.'},
    {'char': '"', 'risk_level': 3, 'risk': 'High', 'reason': 'String quoting character. Breaks simple quoting.'},

    # --- Level 4: Very High Risk ---
    {'char': '<', 'risk_level': 4, 'risk': 'Very High', 'reason': 'Shell redirection. Fundamentally unsafe unquoted.'},
    {'char': '>', 'risk_level': 4, 'risk': 'Very High', 'reason': 'Shell redirection. Fundamentally unsafe unquoted.'},
    {'char': '|', 'risk_level': 4, 'risk': 'Very High', 'reason': 'Shell pipe. Fundamentally unsafe unquoted.'},
    {'char': '&', 'risk_level': 4, 'risk': 'Very High', 'reason': 'Shell background/operator, YAML anchor. Fundamentally unsafe unquoted.'},
    {'char': ' ', 'risk_level': 4, 'risk': 'Very High', 'reason': 'Shell argument separator. Always needs quoting.'},
    {'char': '\\', 'risk_level': 4, 'risk': 'Very High', 'reason': 'Escape character. Causes complex escaping issues.'},
    {'char': '`', 'risk_level': 4, 'risk': 'Very High', 'reason': 'Shell command substitution (legacy). Extremely risky.'},
]


# Default Minimum Safety Policy (can be overridden by checkboxes)
DEFAULT_MIN_REQ_LOWER = True
DEFAULT_MIN_REQ_UPPER = True
DEFAULT_MIN_REQ_DIGITS = True
DEFAULT_MIN_REQ_SPECIAL = False # Default: Don't require *any* special unless asked
DEFAULT_MIN_REQ_EACH_SPECIAL = False # Default: Don't require *each* selected special

# --- Helper Function for Safety Check ---
def meets_minimum_safety(password, check_lower, check_upper, check_digits, check_special,
                         special_chars_pool, require_each_selected_special, selected_specials_list):
    """Checks if a password contains required characters based on flags."""
    found_lower = not check_lower
    found_upper = not check_upper
    found_digit = not check_digits

    # --- Special character check logic ---
    found_special_requirement = True # Assume true unless a check is active and fails
    if check_special and special_chars_pool: # Only check if specials are required and available
        if require_each_selected_special:
            # Must find *all* characters listed in selected_specials_list
            if not selected_specials_list:
                 # If list is empty but check_special=True and require_each=True, this is impossible/contradictory
                 # The calling function should prevent this state. Assume failure if reached.
                 found_special_requirement = False
            else:
                required_set = set(selected_specials_list)
                found_set = set()
                for char in password:
                    if char in required_set:
                        found_set.add(char)
                found_special_requirement = (found_set == required_set)
        else:
            # Original logic: Must find *at least one* character from the pool
            found_any_special = False
            for char in password:
                if char in special_chars_pool:
                    found_any_special = True
                    break
            found_special_requirement = found_any_special

    # --- Check basic types if not already assumed found ---
    if not (found_lower and found_upper and found_digit):
         for char in password:
            if check_lower and not found_lower and char in SAFE_LOWER:
                found_lower = True
            elif check_upper and not found_upper and char in SAFE_UPPER:
                found_upper = True
            elif check_digits and not found_digit and char in SAFE_DIGITS:
                found_digit = True
            # Early exit if basic types are found
            if found_lower and found_upper and found_digit:
                 break

    return found_lower and found_upper and found_digit and found_special_requirement


# --- Password Generation Logic ---
def generate_password(length=16, use_lower=True, use_upper=True, use_digits=True, use_special=True,
                      special_chars_pool="", # Now determined by selections
                      selected_specials_list=None, # The actual list selected
                      req_lower=True, req_upper=True, req_digits=True, req_special=False, # Require *any* special
                      require_each_selected_special=False, # Require *each* selected
                      max_attempts=100):
    """Generates a password using the specified character pool and requirements."""

    if selected_specials_list is None:
        selected_specials_list = []

    # --- Character Source Setup ---
    char_sources = []           # List of strings for the overall pool
    guaranteed_chars = []       # List of characters that *must* be included

    if use_lower:
        char_sources.append(SAFE_LOWER)
        if req_lower: guaranteed_chars.append(secrets.choice(SAFE_LOWER))
    if use_upper:
        char_sources.append(SAFE_UPPER)
        if req_upper: guaranteed_chars.append(secrets.choice(SAFE_UPPER))
    if use_digits:
        char_sources.append(SAFE_DIGITS)
        if req_digits: guaranteed_chars.append(secrets.choice(SAFE_DIGITS))

    # Handle specials based on the *actual pool* derived from selections
    active_special_pool = ""
    if use_special and special_chars_pool:
        active_special_pool = special_chars_pool
        char_sources.append(active_special_pool)

        # Guarantee logic depends on flags
        if require_each_selected_special:
            # Guarantee ALL selected specials
            guaranteed_chars.extend(selected_specials_list) # Add all from the list
        elif req_special:
            # Guarantee *one* random char from the *active* pool
            if active_special_pool: # Ensure pool isn't empty
                 guaranteed_chars.append(secrets.choice(active_special_pool))

    if not char_sources:
        raise ValueError("No character types selected or available.")

    # --- Length Validation (Crucial for require_each_selected_special) ---
    # Remove duplicates from guaranteed_chars *before* checking length
    unique_guaranteed_chars = list(dict.fromkeys(guaranteed_chars))
    minimum_possible_length = len(unique_guaranteed_chars)

    if length < minimum_possible_length:
        req_list_str = "".join(sorted(unique_guaranteed_chars))
        raise ValueError(
            f"Password length ({length}) is too short. Minimum required length to guarantee "
            f"one of each required type ('{req_list_str}') is {minimum_possible_length}."
        )

    # --- Generation Loop ---
    full_char_pool = "".join(char_sources)
    if not full_char_pool: # Safety check
         raise ValueError("Internal error: Character pool became empty.")

    for attempt in range(max_attempts):
        # Start with the unique guaranteed characters for this attempt
        current_guaranteed = list(unique_guaranteed_chars)

        # Fill remaining length randomly from the full pool
        remaining_length = length - len(current_guaranteed)
        if remaining_length < 0: # Should be caught by length check, but safeguard
            remaining_length = 0
        remaining_chars = [secrets.choice(full_char_pool) for _ in range(remaining_length)]

        # Combine and Shuffle
        password_list = current_guaranteed + remaining_chars
        random.shuffle(password_list)
        candidate_password = "".join(password_list)

        # --- Final Safety Check ---
        # Determine which checks are active based on user request flags AND if the type is enabled
        check_req_lower = req_lower and use_lower
        check_req_upper = req_upper and use_upper
        check_req_digits = req_digits and use_digits
        # Special check is active if *either* requirement flag is set AND specials are enabled AND pool not empty
        check_req_special_active = (req_special or require_each_selected_special) and use_special and active_special_pool

        if meets_minimum_safety(candidate_password,
                                check_req_lower, check_req_upper, check_req_digits, check_req_special_active,
                                active_special_pool, require_each_selected_special, selected_specials_list):
            return candidate_password # Password meets all criteria

    # If loop finishes without success
    raise ValueError(
        f"Failed to generate a password meeting minimum requirements within {max_attempts} attempts. "
        "Try increasing length or adjusting requirements (especially 'Require each')."
    )

# --- Flask Routes ---
@app.route('/', methods=['GET', 'POST'])
def index():
    password = None
    error = None

    # Initial default form values for GET request
    # Pre-select the default "safe" special characters
    form_values = {
        'length': 20,
        'use_lower': True,
        'use_upper': True,
        'use_digits': True,
        'use_special': True, # Enable special section by default
        'require_special': DEFAULT_MIN_REQ_SPECIAL, # Default policy for 'any' special
        'require_each_selected_special': DEFAULT_MIN_REQ_EACH_SPECIAL, # Default policy for 'each'
        'selected_specials': list(DEFAULT_SAFE_SPECIAL) # Default selected chars
    }

    if request.method == 'POST':
        try:
            # Get standard form data
            length = int(request.form.get('length', form_values['length']))
            use_lower = 'use_lower' in request.form
            use_upper = 'use_upper' in request.form
            use_digits = 'use_digits' in request.form
            use_special = 'use_special' in request.form # Main toggle for special chars section
            require_special_checked = 'require_special' in request.form # Require *any* selected
            require_each_special_checked = 'require_each_selected_special' in request.form # Require *each* selected

            # Get the list of individually selected special characters
            selected_specials_list = request.form.getlist('selected_specials')

            # --- Determine the effective special character pool ---
            effective_special_pool = ""
            if use_special:
                # Only include selected characters in the pool
                effective_special_pool = "".join(selected_specials_list)
                # Validation: Check for conflicts if requirements are set but no specials selected
                if not selected_specials_list:
                    if require_each_special_checked:
                         raise ValueError("Cannot 'Require each selected special' when no special characters are selected.")
                    if require_special_checked:
                         raise ValueError("Cannot 'Require any special' when no special characters are selected.")
                    # If use_special is checked but no specials selected and no requirements, the pool is just empty.

            # Update form_values to reflect the submitted state for re-rendering
            form_values.update({
                'length': length,
                'use_lower': use_lower,
                'use_upper': use_upper,
                'use_digits': use_digits,
                'use_special': use_special,
                'require_special': require_special_checked,
                'require_each_selected_special': require_each_special_checked,
                'selected_specials': selected_specials_list # Store the list of selected chars
            })

            # Further validation
            if length <= 0:
                raise ValueError("Password length must be positive.")
            if not any([use_lower, use_upper, use_digits, use_special]):
                 raise ValueError("At least one character type group (Lower, Upper, Digits, Special) must be enabled.")
            if use_special and not effective_special_pool and (require_special_checked or require_each_special_checked):
                 # This check is slightly redundant due to checks above, but reinforces the logic
                 raise ValueError("Special characters are required, but none were selected.")


            # Determine effective requirement flags to pass to generator
            effective_req_lower = DEFAULT_MIN_REQ_LOWER
            effective_req_upper = DEFAULT_MIN_REQ_UPPER
            effective_req_digits = DEFAULT_MIN_REQ_DIGITS
            # Pass both flags to the generator, it will handle the logic
            effective_req_any_special = require_special_checked
            effective_req_each_special = require_each_special_checked


            # Generate password using the *effective* pool and requirements
            password = generate_password(
                length=length,
                use_lower=use_lower,
                use_upper=use_upper,
                use_digits=use_digits,
                use_special=use_special, # If the section is enabled
                special_chars_pool=effective_special_pool, # Pool based on selections
                selected_specials_list=selected_specials_list, # List of selections
                req_lower=effective_req_lower,
                req_upper=effective_req_upper,
                req_digits=effective_req_digits,
                req_special=effective_req_any_special, # Pass the 'require any' flag state
                require_each_selected_special=effective_req_each_special # Pass the 'require each' flag state
            )
            flash("Password generated successfully!", "success") # Example flash message

        except ValueError as e:
            error = str(e)
            # No need to flash here if error is displayed directly below
            # flash(f"Error: {error}", "danger")
        except Exception as e:
             app.logger.error(f"Unexpected error: {e}", exc_info=True)
             error = "An unexpected server error occurred."
             # flash(f"Error: {error}", "danger")


    # Render the template, passing all necessary data
    return render_template(
        'index.html',
        password=password,
        error=error, # Pass error for direct display
        form_values=form_values, # Includes selected specials and requirement flags
        special_char_info=SPECIAL_CHARACTER_INFO, # List of dicts for the UI
        default_safe_special=DEFAULT_SAFE_SPECIAL # Just for display info
    )

# --- Run the App ---
if __name__ == '__main__':
    # debug=True enables auto-reloading and detailed error pages during development
    # For production, use a proper WSGI server (like Gunicorn or Waitress) and set debug=False
    # Use host='0.0.0.0' to make accessible on your network (use with caution)
    app.run(debug=True, host='127.0.0.1', port=5000)
