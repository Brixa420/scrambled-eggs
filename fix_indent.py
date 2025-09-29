# This script will help fix the indentation in web_app.py


def fix_web_app():
    try:
        with open("web_app.py", "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Find the create_app function
        in_function = False
        fixed_lines = []

        for i, line in enumerate(lines):
            if "def create_app():" in line:
                in_function = True

            if in_function and "if not secret_key:" in line and line.startswith("    "):
                # Fix the indentation for the secret_key block
                fixed_lines.append("    # Generate secure secret key if not set\n")
                fixed_lines.append("    secret_key = os.environ.get('FLASK_SECRET_KEY')\n")
                fixed_lines.append("    if not secret_key:\n")
                fixed_lines.append("        secret_key = generate_secure_token(32)\n")
                fixed_lines.append("        os.environ['FLASK_SECRET_KEY'] = secret_key\n")
                # Skip the original lines we're replacing
                skip_lines = 3  # Number of lines to skip (the original if block)
                i += skip_lines - 1
            else:
                fixed_lines.append(line)

        # Write the fixed content back to the file
        with open("web_app.py", "w", encoding="utf-8") as f:
            f.writelines(fixed_lines)

        print("✅ Fixed indentation in web_app.py")

    except Exception as e:
        print(f"❌ Error fixing indentation: {str(e)}")


if __name__ == "__main__":
    fix_web_app()
