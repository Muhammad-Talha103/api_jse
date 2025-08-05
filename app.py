from flask import Flask, request, jsonify
import uuid

from utils import load_users, save_users, hash_password, check_password, verify_api_key

app = Flask(__name__)

@app.route("/register", methods=["POST"])
def register():
    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json or {}
    full_name = data.get("full_name", "").strip()
    email = data.get("email", "").strip()
    phone = data.get("phone", "").strip()
    password = data.get("password", "")
    confirm_password = data.get("confirm_password", "")

    if not full_name or not email or not password or not confirm_password:
        return jsonify({"error": "Full name, email, password and confirm_password are required"}), 400

    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password should be at least 6 characters"}), 400

    users = load_users()

    for user in users:
        if user["email"] == email:
            return jsonify({"error": "Email already registered"}), 400
        if phone and user.get("phone") == phone:
            return jsonify({"error": "Phone number already registered"}), 400

    hashed = hash_password(password)
    user_id = str(uuid.uuid4())

    users.append({
        "id": user_id,
        "full_name": full_name,
        "email": email,
        "password": hashed,
        "phone": phone
    })

    save_users(users)

    return jsonify({"message": "Registration successful", "user_id": user_id}), 201

@app.route("/login", methods=["POST"])
def login():
    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json or {}
    identifier = data.get("identifier", "").strip()
    password = data.get("password", "")

    if not identifier or not password:
        return jsonify({"error": "Identifier and password are required"}), 400

    users = load_users()

    for user in users:
        if identifier == user.get("email") or identifier == user.get("phone"):
            if check_password(password, user["password"]):
                return jsonify({"message": f"Login successful. Welcome, {user.get('full_name', 'User')}!"})
            else:
                return jsonify({"error": "Incorrect password"}), 401

    return jsonify({"error": "User not found"}), 404

@app.route("/change_password", methods=["POST"])
def change_password():
    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json or {}
    email = data.get("email", "").strip()
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")

    if not email or not current_password or not new_password or not confirm_password:
        return jsonify({"error": "Email, current password, new password and confirm password are required"}), 400

    if new_password != confirm_password:
        return jsonify({"error": "New passwords do not match"}), 400

    if len(new_password) < 6:
        return jsonify({"error": "New password should be at least 6 characters"}), 400

    users = load_users()

    for user in users:
        if user["email"] == email:
            if check_password(current_password, user["password"]):
                user["password"] = hash_password(new_password)
                save_users(users)
                return jsonify({"message": "Password updated successfully"})
            else:
                return jsonify({"error": "Incorrect current password"}), 401

    return jsonify({"error": "User not found"}), 404

@app.route("/forgot_password", methods=["POST"])
def forgot_password():
    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json or {}
    email = data.get("email", "").strip()
    new_password = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")

    if not email or not new_password or not confirm_password:
        return jsonify({"error": "Email, new password and confirm password are required"}), 400

    if new_password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    if len(new_password) < 6:
        return jsonify({"error": "Password should be at least 6 characters"}), 400

    users = load_users()

    for user in users:
        if user["email"] == email:
            user["password"] = hash_password(new_password)
            save_users(users)
            return jsonify({"message": "Password reset successfully"})

    return jsonify({"error": "Email not found"}), 404

@app.route("/users", methods=["GET"])
def list_users():
    if not verify_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    users = load_users()
    sanitized_users = [
        {
            "id": user.get("id"),
            "full_name": user.get("full_name"),
            "email": user.get("email"),
            "phone": user.get("phone")
        } for user in users
    ]
    return jsonify({"users": sanitized_users})

if __name__ == "__main__":
    app.run(debug=True)
