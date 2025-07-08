import streamlit as st
import requests
import jwt
import json

# Streamlit app configuration
st.set_page_config(page_title="OIDC Playground", page_icon="🛠️", initial_sidebar_state="auto")

# Session state configuration
if "id_token" not in st.session_state:
    st.session_state["id_token"] = ""

# Sidebar settings
with st.sidebar:
    st.title("🛠️ OIDC Playground")
    oidc_url = st.text_input("OIDC Issuer URL", placeholder="https://your-oidc-idp-url")

    action = st.radio("Select OIDC Action", [
        "Get OpenID Configuration",
        "Get JWKS",
        "Generate ID Token",
        "Exchange ID Token with Google Cloud STS"
    ])
    
    # Show Submit in sidebar only for the first two actions
    sidebar_submit = None
    if action in ["Get OpenID Configuration", "Get JWKS"]:
        sidebar_submit = st.button("Submit")

# === Sidebar-driven actions ===
if sidebar_submit:
    if not oidc_url.strip():
        st.error("OIDC Issuer URL is required.")
    else:
        try:
            if action == "Get OpenID Configuration":
                res = requests.get(f"{oidc_url}/.well-known/openid-configuration")
                with st.expander("**🧾 OpenID Configuration**", expanded=True):
                    st.json(res.json())

            elif action == "Get JWKS":
                res = requests.get(f"{oidc_url}/jwks.json")
                with st.expander("**🧾 JWKS**", expanded=True):
                    st.json(res.json())

        except Exception as e:
            st.error(f"Error: {e}")

# === Form-based actions ===
if action == "Generate ID Token":
    with st.form("generate_form"):
        st.markdown("Generate a signed ID token from the OIDC IdP server.")
        sub = st.text_input("Subject*", placeholder="test-user", help="Required. Subject claim (`sub`) in the token")
        email = st.text_input("Email*", placeholder="test-user@example.com", help="Required. Email address claim in the token")
        role = st.text_input("Custom Attribute (Optional)", placeholder="reader", help="Optional. Custom attribute claim e.g. role, could be mapped to `attribute.role` in IAM conditions")
        form_submit = st.form_submit_button("Submit")

        if form_submit:
            if not oidc_url.strip():
                st.error("OIDC Issuer URL is required.")
            elif not sub.strip() or not email.strip():
                st.error("Both Subject and Email are required.")
            else:
                try:
                    res = requests.post(f"{oidc_url}/generate-token", json={
                        "sub": sub.strip(),
                        "email": email.strip(),
                        "role": role.strip()
                    })
                    if res.status_code == 200:
                        id_token = res.json()["id_token"]
                        st.session_state["id_token"] = id_token  # Cache the token
                        with st.expander("🔑 **Raw ID Token**", expanded=True):
                            st.code(id_token, language="none")
                        with st.expander("🔍 **Decoded Claims**", expanded=True):
                            decoded = jwt.decode(id_token, options={"verify_signature": False})
                            st.json(decoded)
                    else:
                        st.error(f"Failed with status {res.status_code}")
                        st.json(res.json())
                except Exception as e:
                    st.error(f"Error: {e}")

if action == "Exchange ID Token with Google Cloud STS":
    with st.form("exchange_form"):
        st.markdown("Exchange an ID token for a Google Cloud access token using Security Token Service (STS).")
        token = st.text_area(
            "Signed ID Token*",
            value=st.session_state.get("id_token", ""),
            height=200,
            help="Required. Paste or reuse a previously generated signed ID token"
        )
        audience = st.text_input(
            "Google Cloud STS Audience*",
            placeholder="//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/my-pool/providers/my-provider",
            help="Required. Audience should match your workload identity pool provider’s full resource name"
        )
        form_submit = st.form_submit_button("Submit")

        if form_submit:
            if not oidc_url.strip():
                st.error("OIDC Issuer URL is required.")
            elif not token.strip() or not audience.strip():
                st.error("Both ID Token and Google Cloud STS Audience are required.")
            else:
                try:
                    sts_url = "https://sts.googleapis.com/v1/token"
                    payload = {
                        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                        "audience": audience.strip(),
                        "scope": "https://www.googleapis.com/auth/cloud-platform",
                        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                        "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                        "subject_token": token.strip()
                    }
                    res = requests.post(sts_url, data=payload)
                    with st.expander("🔐 **STS Response**", expanded=True):
                        st.json(res.json())
                except Exception as e:
                    st.error(f"Error: {e}")
