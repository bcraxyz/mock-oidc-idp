import streamlit as st
import requests
import jwt
import json

st.title("Mock OIDC Client")

# === Get base URL from user ===
oidc_url = st.text_input("OIDC Issuer URL (e.g. https://mock-oidc-idp-url)", "")

# === Choose Action ===
action = st.radio("Choose action", [
    "Get OpenID Configuration",
    "Get JWKS",
    "Generate ID Token",
    "Exchange ID Token with GCP STS"
])

# === Input fields depending on action ===
if action == "Generate ID Token":
    sub = st.text_input("Subject (`sub`)", "test-user")
    email = st.text_input("Email", f"{sub}@example.com")
    role = st.text_input("Custom Role", "reader")

elif action == "Exchange ID Token with GCP STS":
    token = st.text_area("ID Token (Paste token from above)", height=200)
    audience = st.text_input("GCP STS Audience (e.g. //iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/my-pool/providers/my-provider)")

# === Action depending on option selected ===
if st.button("Submit"):
    try:
        if action == "Get OpenID Configuration":
            res = requests.get(f"{oidc_url}/.well-known/openid-configuration")
            st.json(res.json())

        elif action == "Get JWKS":
            res = requests.get(f"{oidc_url}/jwks.json")
            st.json(res.json())

        elif action == "Generate ID Token":
            res = requests.post(f"{oidc_url}/generate-token", json={
                "sub": sub,
                "email": email,
                "role": role
            })
            if res.status_code == 200:
                id_token = res.json()["id_token"]
                st.success("Token generated!")
                st.code(id_token, language="none")

                decoded = jwt.decode(id_token, options={"verify_signature": False})
                st.subheader("Decoded Claims")
                st.json(decoded)
            else:
                st.error(f"Failed: {res.status_code}")
                st.json(res.json())

        elif action == "Exchange ID Token with GCP STS":
            sts_url = "https://sts.googleapis.com/v1/token"
            payload = {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "audience": audience,
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                "subject_token": token
            }
            res = requests.post(sts_url, data=payload)
            st.subheader("STS Response")
            st.json(res.json())

    except Exception as e:
        st.error(f"Error: {e}")
