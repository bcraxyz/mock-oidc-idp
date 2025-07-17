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
def get_env_var(key):
    val = os.getenv(key)
    if not val:
        raise RuntimeError(f"{key} environment variable not set")
    return val

PRIVATE_KEY_PEM = get_env_var("PRIVATE_KEY_PEM")
ISSUER_URL = get_env_var("ISSUER_URL")
CLIENT_ID = get_env_var("CLIENT_ID") # id_token 'aud'
AUDIENCE = get_env_var("AUDIENCE")   # access_token 'aud'
KEY_ID = get_env_var("KEY_ID")

# --- Load the private key once when the app starts ---
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
    "jwks_uri": f"{ISSUER_URL}/.well-known/jwks.json",
    "authorization_endpoint": f"{ISSUER_URL}/authorize",
    "token_endpoint": f"{ISSUER_URL}/token",
    "response_types_supported": ["code", "id_token", "token id_token"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "scopes_supported": ["openid", "email"],
}

# --- Flask Routes ---
@app.route('/.well-known/openid-configuration')
def openid_configuration():
    return jsonify(OPENID_CONFIG_DATA)

@app.route('/.well-known/jwks.json')
def jwks_json():
    return jsonify(JWKS_DATA)

@app.route('/token', methods=['POST'])
def generate_token():
    req_data = request.get_json() if request.is_json else request.args
    subject = req_data.get('sub')
    email = req_data.get('email')

    now = int(time.time())
    id_payload = {
        "iss": ISSUER_URL,
        "sub": subject,
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 3600,  # Token valid for 1 hour
        "auth_time": int(time.time()),
        "jti": os.urandom(16).hex()
    }
    if email:
        id_payload["email"] = email

    access_payload = {
        "iss": ISSUER_URL,
        "sub": subject,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 3600,  # Token valid for 1 hour
        "auth_time": int(time.time()),
        "jti": os.urandom(16).hex()
    }

    headers = {
        "kid": KEY_ID,
        "alg": "RS256"
    }

    try:
        id_token = jwt.encode(
            id_payload,
            private_key,
            algorithm="RS256",
            headers=headers
        )
        access_token = jwt.encode(
            access_payload, 
            private_key, 
            algorithm="RS256", 
            headers=headers
        )
        return jsonify({
          "access_token": access_token,
          "id_token": id_token,
          "token_type": "Bearer",
          "expires_in": 3600
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to generate tokens: {str(e)}"}), 500

@app.route('/authorize')
def authorize_stub():
    # For clients expecting this path in a real OIDC provider
    return jsonify({"error": "Not implemented", "message": "This is a mock OIDC provider"}), 501
    
@app.route('/')
def health_check():
    return jsonify({"status": "ok", "message": "Mock OIDC IdP running..."}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
