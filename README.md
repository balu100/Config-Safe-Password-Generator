# Advanced Config-Safe Password Generator Web UI

A Flask web application for generating cryptographically secure passwords with a focus on compatibility with configuration files (YAML, TOML, INI) and shell environments (like Ansible). It provides granular control over included character types and detailed risk assessment for special characters.

![Screenshot Placeholder](images/screenshot.png) 
*(Suggestion: Replace the above line with an actual screenshot path/link after creating one)*

## Features

*   **Web-Based GUI:** Easy-to-use interface built with Flask.
*   **Cryptographically Secure:** Uses Python's `secrets` module for strong randomness.
*   **Customizable Length:** Specify the desired password length.
*   **Selectable Character Types:** Independently include/exclude:
    *   Lowercase letters (a-z)
    *   Uppercase letters (A-Z)
    *   Digits (0-9)
*   **Granular Special Character Control:**
    *   Enable/disable the use of special characters globally.
    *   Individually select which special characters to include from a predefined list.
    *   **Risk Assessment:** Each special character is categorized into 5 risk levels based on potential compatibility issues:
        *   `Very Low`: Generally safe (`_`)
        *   `Low`: Usually safe when quoted (`@`, `.`, `,`, `+`, `?`, `/`)
        *   `Medium`: Often requires quoting (`-`, `=`, `%`, `^`, `~`, `:`)
        *   `High`: Core syntax/quoting characters (`#`, `;`, `$`, `!`, `*`, `()`, `[]`, `{}`, `'`, `"`)
        *   `Very High`: Fundamentally problematic/unsafe unquoted (`<`, `>`, `|`, `&`, ` `, `\`, `` ` ``)
*   **Requirement Options:**
    *   Optionally require *at least one* character from the pool of *selected* special characters.
    *   Optionally require *one of each* individually *selected* special character (increases minimum length requirement).
*   **Password Strength Estimation:** Provides an estimated entropy (in bits) and a visual strength meter based on selected options.
*   **Copy to Clipboard:** Easily copy the generated password.
*   **Responsive Design:** Basic responsiveness for different screen sizes.

## Requirements

*   Python 3.7+
*   Flask (`pip install Flask`)

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/flask-password-generator.git # Replace with your repo URL
    cd flask-password-generator # Replace with your directory name
    ```
2.  **Install dependencies:**
    ```bash
    pip install Flask
    # Or if a requirements.txt file is provided:
    # pip install -r requirements.txt
    ```
3.  **Ensure File Structure:** Make sure you have the following structure:
    ```
    your-repo-directory/
    ├── app.py
    └── templates/
        └── index.html
    ```

## Usage

1.  **Run the Flask application:**
    ```bash
    python app.py
    ```
2.  **Access the application:** Open your web browser and navigate to:
    `http://127.0.0.1:5000` (or the address provided in the terminal).

3.  **Use the Interface:**
    *   Adjust the desired password length.
    *   Select the basic character types (lowercase, uppercase, digits).
    *   Enable "Include Special Characters" to reveal the special character options.
    *   Check the individual special characters you want to allow in the grid. Note their risk levels.
    *   Optionally, check "Require any selected special" or "Require each selected special".
    *   Monitor the estimated password strength.
    *   Click "Generate Secure Password".
    *   Copy the generated password using the "Copy" button.

**Note:** The application runs in debug mode by default (`debug=True`). For production deployment, use a proper WSGI server (like Gunicorn or Waitress) and set `debug=False`.

## Technical Details

*   **Backend:** Python, Flask
*   **Frontend:** HTML, CSS, JavaScript (vanilla)
*   **Templating:** Jinja2 (via Flask)
*   **Security:** Uses `secrets.choice()` for generating cryptographically secure random characters.
*   **Config-Safety Philosophy:** The special character risk levels are designed to guide users towards creating passwords that are less likely to conflict with syntax in common configuration files (YAML, TOML, INI, JSON strings) and shell environments. Higher-risk characters *can* be used but are more likely to require careful quoting or escaping in those contexts.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or open an Issue.
*(Optional: Add more specific contribution guidelines if desired)*

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
*(Suggestion: Create a LICENSE file with the MIT License text or choose another appropriate license)*
