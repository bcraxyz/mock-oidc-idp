import jwt
import datetime
import time
import os
import json
from flask import Flask, request, jsonify, send_from_directory
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# --- Configuration (loaded from environment variables) ---
PRIVATE_KEY_PEM = os.environ.get("PRIVATE_KEY_PEM")
if not PRIVATE_KEY_PEM:
    raise ValueError("PRIVATE_KEY_PEM environment variable not set.")

# This will be the public URL of your Cloud Run service!
ISSUER_URL = os.environ.get("ISSUER_URL") 
if not ISSUER_URL:
    raise ValueError("ISSUER_URL environment variable not set.")

AUDIENCE = os.environ.get("AUDIENCE")
if not AUDIENCE:
    raise ValueError("AUDIENCE environment variable not set.")

KEY_ID = os.environ.get("KEY_ID")
if not KEY_ID:
    raise ValueError("KEY_ID environment variable not set.")

# Load the private key once when the app starts
try:
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PEM.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    # Also derive the public key components for JWKS
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    n_jwk = jwt.utils.base64url_encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8')
    e_jwk = jwt.utils.base64url_encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8')

except Exception as e:
    raise ValueError(f"Failed to load private key or derive public key components: {e}")

# --- JWKS and OpenID Configuration Data ---
JWKS_DATA = {
    "keys": [
        {
            "kty": "RSA",
            "kid": KEY_ID,
            "n": n_jwk,
            "e": e_jwk,
            "alg": "RS256",
            "use": "sig"
        }
    ]
}

OPENID_CONFIG_DATA = {
    "issuer": ISSUER_URL,
    "jwks_uri": f"{ISSUER_URL}/jwks.json", # jwks.json will be served by this app
    "response_types_supported": ["id_token"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"]
}

# --- Flask Routes ---

@app.route('/.well-known/openid-configuration')
def openid_configuration():
    return jsonify(OPENID_CONFIG_DATA)

@app.route('/jwks.json')
def jwks_json():
    return jsonify(JWKS_DATA)

@app.route('/generate-token', methods=['GET', 'POST'])
def generate_token():
    req_data = request.get_json() if request.is_json else request.args
    
    subject = req_data.get('sub', 'default-test-subject')
    email = req_data.get('email', f'{subject}@example.com')
    custom_role = req_data.get('role', 'user')

    now = datetime.datetime.utcnow()
    payload = {
        "iss": ISSUER_URL,
        "sub": subject,
        "aud": AUDIENCE,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,  # Token valid for 1 hour
        "auth_time": int(time.time()),
        "jti": os.urandom(16).hex(),
        "email": email,
        "https://example.com/custom_role": custom_role
    }

    headers = {
        "kid": KEY_ID,
        "alg": "RS256"
    }

    try:
        encoded_jwt = jwt.encode(
            payload,
            private_key,
            algorithm="RS256",
            headers=headers
        )
        return jsonify({"id_token": encoded_jwt, "subject": subject}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to generate token: {str(e)}"}), 500

@app.route('/')
def health_check():
    return "Mock OIDC IdP and Token Generator is running on port 8080."

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
