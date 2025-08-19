import jwt
import json
import requests
import streamlit as st

# Streamlit app configuration
st.set_page_config(page_title="OIDC Playground", page_icon="🛠️", initial_sidebar_state="auto")

# Session state configuration
if "id_token" not in st.session_state:
    st.session_state["id_token"] = ""
if "federated_token" not in st.session_state:
    st.session_state["federated_token"] = ""
if "sa_access_token" not in st.session_state:
    st.session_state["sa_access_token"] = ""
if "openid_config" not in st.session_state:
    st.session_state["openid_config"] = None
if "jwks_uri" not in st.session_state:
    st.session_state["jwks_uri"] = ""

# Sidebar settings
with st.sidebar:
    st.title("🛠️ OIDC Playground")
    oidc_url = st.text_input("OIDC Issuer URL", placeholder="https://your-oidc-idp-url")

    action = st.radio("Select OIDC Action", [
        "Get OpenID Configuration",
        "Get JWKS",
        "Generate ID Token",
        "Exchange ID Token with Google Cloud STS",
        "Impersonate Service Account",
        "List GCS Buckets"
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
                res.raise_for_status()
                st.session_state["openid_config"] = res.json()
                st.session_state["jwks_uri"] = res.json().get("jwks_uri", "")
                with st.expander("**🧾 OpenID Configuration**", expanded=True):
                    st.json(st.session_state["openid_config"])

            elif action == "Get JWKS":
                jwks_url = st.session_state.get("jwks_uri")
                if not jwks_url:
                    jwks_url = f"{oidc_url}/.well-known/jwks.json"
                res = requests.get(jwks_url)
                res.raise_for_status()
                with st.expander("**🧾 JWKS**", expanded=True):
                    st.json(res.json())

        except requests.exceptions.HTTPError as e:
            st.error(f"HTTP Error: {e.response.status_code} - {e.response.text}")
        except Exception as e:
            st.error(f"Error: {e}")

# === Form-based actions ===
if action == "Generate ID Token":
    with st.form("generate_form"):
        st.markdown("Generate a signed ID token from the OIDC IdP server.")
        sub = st.text_input("Subject*", placeholder="gcs-sa", help="Required. Subject claim (`sub`) in the token")
        email = st.text_input("Email", placeholder="gcs-sa@your-project-id.iam.gserviceaccount.com", help="Optional. Email address claim in the token")
        form_submit = st.form_submit_button("Submit")

        if form_submit:
            if not oidc_url.strip():
                st.error("OIDC Issuer URL is required.")
            elif not sub.strip():
                st.error("Subject is required.")
            else:
                try:
                    payload = {"sub": sub.strip()}
                    if email.strip():
                        payload["email"] = email.strip()
                    res = requests.post(f"{oidc_url}/token", json=payload)
                    
                    if res.status_code == 200:
                        id_token = res.json()["id_token"]
                        access_token = res.json()["access_token"]
                        st.session_state["id_token"] = id_token  # Cache the token

                        if id_token:
                            with st.expander("🔑 **Raw ID Token**", expanded=True):
                                st.code(id_token, language="none")
                            with st.expander("🔍 **Decoded ID Token Claims**", expanded=True):
                                try:
                                    decoded_id = jwt.decode(id_token, options={"verify_signature": False})
                                    st.json(decoded_id)
                                except Exception as e:
                                    st.warning("Could not decode ID token: {e}")
                        if access_token:
                            with st.expander("🔑 **Raw Access Token**", expanded=False):
                                st.code(access_token, language="none")
                            with st.expander("🔍 **Decoded Access Token Claims**", expanded=False):
                                try:
                                    decoded_access = jwt.decode(access_token, options={"verify_signature": False})
                                    st.json(decoded_access)
                                except Exception as e:
                                    st.warning(f"Could not decode access token: {e}")
                    else:
                        st.error(f"Failed with status {res.status_code}")
                        st.json(res.json())
                except Exception as e:
                    st.error(f"Error: {e}")

elif action == "Exchange ID Token with Google Cloud STS":
    with st.form("exchange_form"):
        st.markdown("Exchange an ID token for a Google Cloud federated token using Security Token Service (STS).")
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
                    res_json = res.json()
                    with st.expander("🔐 **STS Response (Federated Token)**", expanded=True):
                        st.json(res.json())
                    
                    # Extract and store federated token if present
                    federated_token = res_json.get("access_token")
                    if federated_token:
                        st.session_state["federated_token"] = federated_token
                    else:
                        st.warning("No access token found in response.")
                except Exception as e:
                    st.error(f"Error: {e}")

elif action == "Impersonate Service Account":
    with st.form("impersonate_form"):
        st.markdown("Use the federated token to impersonate your service account and get a service account access token.")
        
        federated_token = st.text_area(
            "Federated Token*",
            value=st.session_state.get("federated_token", ""),
            height=200,
            help="Required. Paste or reuse a previously generated federated token from the STS exchange"
        )
        
        service_account_email = st.text_input(
            "Service Account Email*",
            placeholder="gcs-sa@your-project.iam.gserviceaccount.com",
            help="Required. The email of the service account to impersonate"
        )
        
        form_submit = st.form_submit_button("Submit")

        if form_submit:
            if not federated_token.strip() or not service_account_email.strip():
                st.error("Both Federated Token and Service Account Email are required.")
            else:
                try:
                    # Impersonate the service account
                    impersonation_url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{service_account_email.strip()}:generateAccessToken"
                    
                    headers = {
                        "Authorization": f"Bearer {federated_token.strip()}",
                        "Content-Type": "application/json"
                    }
                    
                    payload = {
                        "scope": ["https://www.googleapis.com/auth/cloud-platform"],
                        "lifetime": "3600s"  # 1 hour
                    }
                    
                    res = requests.post(impersonation_url, headers=headers, json=payload)
                    
                    if res.status_code == 200:
                        sa_access_token = res.json()["accessToken"]
                        st.session_state["sa_access_token"] = sa_access_token
                        
                        with st.expander("🔐 **Service Account Access Token**", expanded=True):
                            st.json(res.json())
                    else:
                        st.error(f"Service account impersonation failed: {res.status_code}")
                        with st.expander("🚨 **Error Response**", expanded=True):
                            st.json(res.json())
                        
                except Exception as e:
                    st.error(f"Error: {e}")

elif action == "List GCS Buckets":
    with st.form("access_form"):
        st.markdown("List GCS buckets using the service account access token (not the federated token).")
        sa_access_token = st.text_area(
            "Service Account Access Token*",
            value=st.session_state.get("sa_access_token", ""),
            height=200,
            help="Required. Paste or reuse a previously generated service account access token"
        )
        gcs_project = st.text_input("Google Cloud Project ID*", help="Required. Project to list GCS buckets from")
        form_submit = st.form_submit_button("Submit")

        if form_submit:
            if not sa_access_token.strip() or not gcs_project.strip():
                st.error("Both Service Account Access Token and Google Cloud Project ID are required.")
            else:
                try:
                    headers = {
                        "Authorization": f"Bearer {sa_access_token.strip()}"
                    }
                    gcs_url = f"https://storage.googleapis.com/storage/v1/b?project={gcs_project.strip()}"
                    res = requests.get(gcs_url, headers=headers)
                    with st.expander("📦 **GCS Response**", expanded=True):
                        st.json(res.json())
                    if res.status_code == 200:
                        buckets = res.json().get("items", [])
                except Exception as e:
                    st.error(f"Error: {e}")
