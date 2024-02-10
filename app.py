from flask import Flask, render_template, request, jsonify
import random
import string
import re

app = Flask(__name__)

def password_generator(length, symbols):
    characters = string.ascii_letters + string.digits
    if symbols:
        characters += string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def check_password_strength(password):
    min_length = 8
    uppercase_regex = re.compile(r'[A-Z]')
    lowercase_regex = re.compile(r'[a-z]')
    digit_regex = re.compile(r'\d')
    special_char_regex = re.compile(r'[!@#$%^&*()_+{}[\]:;<>,.?~\\/-]')

    if len(password) < min_length:
        return "Weak: Password should be at least {} characters long".format(min_length)

    if not uppercase_regex.search(password) or not lowercase_regex.search(password):
        return "Weak: Password should contain at least one uppercase and one lowercase letter"

    if not digit_regex.search(password):
        return "Weak: Password should contain at least one digit"

    if not special_char_regex.search(password):
        return "Weak: Password should contain at least one special character"

    return "Strong: Password meets the criteria"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate-password', methods=['GET'])
def generate_password():
    try:
        length = int(request.args.get('length', 12))
        symbols = request.args.get('symbols', 'false').lower() == 'true'
        password = password_generator(length, symbols)
        return jsonify({"password": password})
    except ValueError:
        return jsonify({"error": "Invalid length parameter. Please provide a valid integer."}), 400

@app.route('/check-password', methods=['GET'])
def check_password():
    password_input = request.args.get('password', '')
    result = check_password_strength(password_input)
    return jsonify({"result": result})

if __name__ == "__main__":
    app.run(debug=True)
