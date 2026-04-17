# mobile_app_security_dashboard_merged.py
# Merged Advanced Mobile App Security Dashboard — Neon Blue Edition (merged v2 + enhanced MFA)
# This file includes:
# - Detailed Risk Analysis
# - Separate Encryption & Decryption modules
# - Elaborated Code Obfuscation
# - Interactive Session Handling, Key Management, Permissions Audit
# - Enhanced MFA (TOTP) demo with provisioning URI, QR if available, OTP display & verification
# - Audit log for actions
#
# Dependencies: streamlit, pyotp, cryptography, pandas, requests
# Optional: qrcode, pillow (for QR image). If qrcode is missing, UI will still show provisioning URI for manual entry.

import streamlit as st
import time
import hashlib
import base64
from cryptography.fernet import Fernet
import pyotp
import random
import pandas as pd
from datetime import datetime, timedelta
import requests
import textwrap

# Optional QR generation
try:
    import qrcode
    from PIL import Image
    QR_SUPPORTED = True
except Exception:
    QR_SUPPORTED = False

st.set_page_config(
    page_title="Mobile Application Security Simulation Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Neon Blue Theme ---
st.markdown(""" 
<style>
body {background-color: #020b1b; color: #e6f2ff; font-family: 'Poppins', sans-serif;}
.sidebar .sidebar-content {background: linear-gradient(180deg,#001a33,#000d1a);}
h1,h2,h3,h4,h5 {color: #00bfff;}
.stButton>button {background-color: #004080; color:white; border:none; border-radius:10px; padding:0.45rem 1rem;}
.stButton>button:hover {background-color: #0066cc; transform: scale(1.03);}
.card {background: rgba(0,30,60,0.6); border-radius:14px; padding:16px; box-shadow: 0 0 12px rgba(0,191,255,0.22);}
.codebox {background: rgba(255,255,255,0.03); padding:12px; border-radius:8px;}
</style>
""", unsafe_allow_html=True)

st.title("Advanced Mobile Security App")

# --- Audit Log System ---
if "audit_log" not in st.session_state:
    st.session_state.audit_log = []

def add_log(action):
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.audit_log.append({"time": timestamp, "action": action})

# --- Sidebar Navigation ---
menu = st.sidebar.radio(
    "🔐 Security Modules",
    (
        "📊 Risk Analysis",
        "🔍 Detailed Risk Analysis",
        "🧱 Architecture",
        "🔑 Encryption",
        "🔓 Decryption",
        "🌐 HTTPS Check",
        "🕒 MFA (TOTP)",
        "🧰 Session Handling",
        "🧮 Key Management",
        "🧩 Code Obfuscation",
        "📡 Network Monitor",
        "🧬 Malware Scan",
        "🔒 Permissions Audit",
        "🤖 AI Threat Detection",
        "📱 Device Security Check",
        "📜 Audit Log",
    ),
)

# --- Utility Functions ---
def generate_key():
    key = Fernet.generate_key()
    add_log("Generated encryption key")
    return key

def encrypt_data(key, data):
    f = Fernet(key)
    encrypted = f.encrypt(data.encode())
    add_log("Encrypted data")
    return encrypted

def decrypt_data(key, encrypted):
    try:
        f = Fernet(key)
        # accept bytes or str
        token = encrypted
        if isinstance(token, str):
            token = token.encode()
        decrypted = f.decrypt(token).decode()
        add_log("Decrypted data")
        return decrypted
    except Exception as e:
        add_log(f"Failed decryption: {e}")
        raise

def get_totp(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()

def ai_threat_detection():
    score = random.randint(70, 99)
    status = "Safe" if score >= 85 else "Risky"
    add_log(f"AI Threat Detection: {score}% confidence, status: {status}")
    return score, status

def device_security_check():
    root = random.choice(["Yes", "No"])
    integrity = random.choice(["OK ✅", "Compromised ❌"])
    add_log(f"Device Security Check: Root={root}, Integrity={integrity}")
    return root, integrity

# --- Modules ---

# 1. Compact Risk Analysis (summary)
if menu == "📊 Risk Analysis":
    st.subheader("📊 Risk Analysis — Summary")
    st.write("Quick simulated risk scoring for mobile app (click Detailed for full view).")
    risk_score = random.randint(45, 95)
    st.progress(risk_score)
    st.info(f"Risk Score: {risk_score}/100")
    add_log("Viewed Risk Analysis (summary)")

# 2. Detailed Risk Analysis
elif menu == "🔍 Detailed Risk Analysis":
    st.subheader("🔍 Detailed Risk Analysis")
    st.write("Breakdown of findings, weighted scoring, and recommended mitigations.")
    with st.expander("1) Select findings (toggle)"):
        insecure_storage = st.checkbox("Sensitive data stored unencrypted", value=False)
        insecure_communication = st.checkbox("Uses HTTP or insecure TLS config", value=False)
        excessive_permissions = st.checkbox("App requests excessive permissions", value=False)
        outdated_libs = st.checkbox("Uses outdated libraries with known CVEs", value=False)
        weak_auth = st.checkbox("Weak or missing authentication checks", value=False)
        poor_input_validation = st.checkbox("Poor input validation (possible injections)", value=False)
    add_log("Configured Detailed Risk Analysis findings")

    weights = {
        "insecure_storage": 25,
        "insecure_communication": 20,
        "excessive_permissions": 15,
        "outdated_libs": 15,
        "weak_auth": 15,
        "poor_input_validation": 10,
    }

    score = 100
    issues = []
    if insecure_storage:
        score -= weights["insecure_storage"]; issues.append("Insecure Storage")
    if insecure_communication:
        score -= weights["insecure_communication"]; issues.append("Insecure Communication")
    if excessive_permissions:
        score -= weights["excessive_permissions"]; issues.append("Excessive Permissions")
    if outdated_libs:
        score -= weights["outdated_libs"]; issues.append("Outdated Libraries")
    if weak_auth:
        score -= weights["weak_auth"]; issues.append("Weak Authentication")
    if poor_input_validation:
        score -= weights["poor_input_validation"]; issues.append("Poor Input Validation")

    st.markdown("### Risk Breakdown & Score")
    st.metric("Overall Risk Score", f"{score}/100", delta=f"-{100-score}")
    breakdown = [
        {"component": "Data Protection", "weight": weights["insecure_storage"], "issue": "Yes" if insecure_storage else "No"},
        {"component": "Communication Security", "weight": weights["insecure_communication"], "issue": "Yes" if insecure_communication else "No"},
        {"component": "Permissions", "weight": weights["excessive_permissions"], "issue": "Yes" if excessive_permissions else "No"},
        {"component": "Dependencies", "weight": weights["outdated_libs"], "issue": "Yes" if outdated_libs else "No"},
        {"component": "Authentication", "weight": weights["weak_auth"], "issue": "Yes" if weak_auth else "No"},
        {"component": "Input Validation", "weight": weights["poor_input_validation"], "issue": "Yes" if poor_input_validation else "No"},
    ]
    df_break = pd.DataFrame(breakdown)
    st.table(df_break)
    add_log("Viewed Detailed Risk Breakdown")

    st.markdown("### Recommended Mitigations")
    if insecure_storage:
        st.write("- Encrypt sensitive data at rest (AES-256). Use platform keystore (Android Keystore / iOS Keychain).")
    if insecure_communication:
        st.write("- Enforce TLS 1.2+ with strong ciphers; use certificate pinning for critical endpoints.")
    if excessive_permissions:
        st.write("- Apply least privilege; request permissions only when required and explain to users.")
    if outdated_libs:
        st.write("- Update dependencies regularly; use SCA tooling to track CVEs.")
    if weak_auth:
        st.write("- Use multi-factor auth, rotate tokens, and enforce server-side session checks.")
    if poor_input_validation:
        st.write("- Validate & sanitize inputs server-side; use parameterized queries.")
    if not issues:
        st.success("No issues selected — simulation shows healthy app.")
    add_log("Displayed mitigation recommendations")

    if st.button("Export Risk Report (CSV)"):
        report = df_break.copy()
        report["overall_score"] = score
        csv = report.to_csv(index=False)
        st.download_button("Download CSV", data=csv, file_name="risk_report.csv", mime="text/csv")
        add_log("Exported Risk Report")

# 3. Architecture
elif menu == "🧱 Architecture":
    st.subheader("🧱 Layered Security Architecture")
    st.markdown("Explore recommended controls per layer:")
    with st.expander("Data Layer 🔒"):
        st.write("Best practices: encrypted storage, tokenization, secure backups, access controls.")
        st.code(textwrap.dedent('''            Example: Store only hashes for passwords, use PBKDF2/Argon2 for key derivation,
            use platform keystore for symmetric keys.
        '''), language="text")
        add_log("Viewed Data Layer details")
    with st.expander("Network Layer 🌐"):
        st.write("Best practices: enforce HTTPS, certificate pinning, mutual TLS for critical services, network segmentation.")
        add_log("Viewed Network Layer details")
    with st.expander("Application Layer 🧩"):
        st.write("Best practices: input validation, rate limiting, secure APIs, code obfuscation, runtime checks.")
        add_log("Viewed Application Layer details")

# 4. Encryption
elif menu == "🔑 Encryption":
    st.subheader("🔑 Encryption — Encrypt plaintext with a generated Fernet key")
    if "generated_key" not in st.session_state:
        st.session_state.generated_key = generate_key()
        st.session_state.thumbprint = hashlib.sha256(st.session_state.generated_key).hexdigest()
    st.code(f"Key: {st.session_state.generated_key}\nThumbprint: {st.session_state.thumbprint}", language="text")
    plaintext = st.text_area("Enter plaintext to encrypt:", height=120)
    if st.button("Encrypt text"):
        if plaintext.strip() == "":
            st.warning("Enter some text first")
        else:
            encrypted = encrypt_data(st.session_state.generated_key, plaintext)
            st.code(encrypted, language="text")
            st.success("Encryption complete — you can copy the encrypted output and use Decryption module.")
            add_log("Performed encryption")

# 5. Decryption
elif menu == "🔓 Decryption":
    st.subheader("🔓 Decryption — Paste Fernet key and encrypted token to decrypt")
    key_input = st.text_input("Fernet Key (paste exactly as shown in Encryption):")
    encrypted_input = st.text_area("Encrypted token (as shown by Encryption):", height=120)
    if st.button("Decrypt"):
        if not key_input or not encrypted_input:
            st.warning("Provide both key and encrypted token.")
        else:
            try:
                key_bytes = key_input.encode() if isinstance(key_input, str) else key_input
                token = encrypted_input.strip()
                # handle Python bytes repr
                if token.startswith("b'") or token.startswith('b"'):
                    token = token[2:-1]
                token_bytes = token.encode() if isinstance(token, str) else token
                decrypted = decrypt_data(key_bytes, token_bytes)
                st.code(decrypted, language="text")
                st.success("Decryption successful")
                add_log("Performed decryption")
            except Exception as e:
                st.error(f"Decryption failed: {e}")
                add_log(f"Decryption failed: {e}")

# 6. HTTPS Check
elif menu == "🌐 HTTPS Check":
    st.subheader("🌐 HTTPS Check")
    url = st.text_input("Enter URL to validate HTTPS:")
    if url:
        try:
            r = requests.get(url, timeout=5)
            valid = "✅ Valid HTTPS" if r.url.startswith("https") else "❌ Not Secure"
            st.success(valid)
            add_log(f"HTTPS Check on {url}: {valid}")
        except Exception as e:
            st.error(f"Error: {e}")
            add_log(f"HTTPS Check failed on {url}")

# 7. MFA (TOTP) — enhanced demo
elif menu == "🕒 MFA (TOTP)":
    st.subheader("🕒 MFA (TOTP) — Interactive Demo")
    if "mfa_secret" not in st.session_state:
        st.session_state.mfa_secret = pyotp.random_base32()
        add_log("Generated MFA secret (initial)")

    col_ctrl, col_info = st.columns([1,2])
    with col_ctrl:
        if st.button("Generate New Secret"):
            st.session_state.mfa_secret = pyotp.random_base32()
            add_log("Generated new MFA secret")
        st.write("Secret (base32):")
        st.code(st.session_state.mfa_secret)
        issuer = st.text_input("Issuer (app name)", value="MyApp")
        account = st.text_input("Account (email/username)", value="user@example.com")
        totp = pyotp.TOTP(st.session_state.mfa_secret)
        provisioning_uri = totp.provisioning_uri(name=account, issuer_name=issuer)
        st.write("Provisioning URI (otpauth):")
        st.code(provisioning_uri, language="text")
        if QR_SUPPORTED:
            try:
                qr = qrcode.make(provisioning_uri)
                st.image(qr, width=200, caption="Scan with Authenticator app")
            except Exception as e:
                st.info("QR generation failed; use the provisioning URI manually.")
        else:
            st.info("QR generation not available (optional dependency missing). Use provisioning URI to add to your authenticator app.")

    with col_info:
        st.markdown("""**What is the secret and how OTP works?**
- Secret: a shared Base32 key stored both on server and in your authenticator app.
- OTP: derived from secret + current time window (usually 30s) using HMAC-SHA1.
- The server verifies the code by computing same algorithm and comparing.
""")
        totp_code = get_totp(st.session_state.mfa_secret)
        st.subheader("Current OTP (for demo)")
        st.code(totp_code, language="text")
        # countdown
        period = 30
        epoch = int(time.time())
        seconds_remaining = period - (epoch % period)
        st.metric("Seconds until code expires", seconds_remaining)

        st.markdown("---")
        st.subheader("Verify OTP")
        user_code = st.text_input("Enter OTP to verify:")
        if st.button("Verify OTP"):
            if not user_code:
                st.warning("Enter the OTP from above or your authenticator app.")
            else:
                ok = pyotp.TOTP(st.session_state.mfa_secret).verify(user_code, valid_window=1)
                if ok:
                    st.success("✅ OTP is valid!")
                    add_log("Verified OTP successfully")
                else:
                    st.error("❌ Invalid OTP. Check secret and clock sync.")
                    add_log("Failed OTP verification")

        st.markdown("Demo: Codes across time windows")
        demo_table = []
        now = int(time.time())
        for offset in (-60, -30, 0, 30, 60):
            ts = now + offset
            code = pyotp.TOTP(st.session_state.mfa_secret).at(ts)
            demo_table.append({'offset_s': offset, 'timestamp': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'), 'code': code})
        st.table(pd.DataFrame(demo_table))
        add_log("Displayed MFA demo codes")

# 8. Session Handling
elif menu == "🧰 Session Handling":
    st.subheader("🧰 Session Handling")
    if "session_token" not in st.session_state:
        st.session_state.session_token = None
        st.session_state.token_expiry = None

    if st.button("Generate Session Token"):
        st.session_state.session_token = base64.urlsafe_b64encode(Fernet.generate_key()).decode()
        st.session_state.token_expiry = datetime.now() + timedelta(minutes=1)
        add_log("Session token generated")
    if st.session_state.session_token:
        if datetime.now() > st.session_state.token_expiry:
            st.warning("Session token expired! Generate a new one.")
            st.session_state.session_token = None
        else:
            st.code(st.session_state.session_token, language="text")
            st.info(f"Expires at: {st.session_state.token_expiry.strftime('%H:%M:%S')}")
            if st.button("Copy token to clipboard (browser)"):
                token_js = f"""<script>navigator.clipboard.writeText('{st.session_state.session_token}');</script>"""
                st.markdown(token_js, unsafe_allow_html=True)
                st.success("Token copied to clipboard (browser).")

# 9. Key Management
elif menu == "🧮 Key Management":
    st.subheader("🧮 Key Management / Thumbprint")
    if st.button("Generate New Key"):
        st.session_state.generated_key = generate_key()
        st.session_state.thumbprint = hashlib.sha256(st.session_state.generated_key).hexdigest()
        add_log("Generated new key")
    if "generated_key" in st.session_state:
        st.code(f"Key: {st.session_state.generated_key}\nThumbprint: {st.session_state.thumbprint}", language="text")
        if st.button("Copy Key to clipboard (browser)"):
            try:
                key_str = st.session_state.generated_key.decode()
            except Exception:
                key_str = str(st.session_state.generated_key)
            key_js = f"<script>navigator.clipboard.writeText('{key_str}');</script>"
            st.markdown(key_js, unsafe_allow_html=True)
            st.success("Key copied to clipboard (browser).")

# 10. Code Obfuscation (elaborated)
elif menu == "🧩 Code Obfuscation":
    st.subheader("🧩 Code Obfuscation — Techniques & Demo")
    st.markdown("""Code obfuscation reduces readability of your code to make reverse engineering harder.
It is **not** a substitute for secure design. Use obfuscation as a defense-in-depth measure.
""")
    st.markdown("""### Common techniques:
- Minification: remove whitespace, shorten identifiers (mostly for JS).
- Identifier renaming: replace readable names with meaningless tokens.
- Control-flow flattening: restructure code flow to be less obvious.
- String encryption: encrypt literal strings and decrypt at runtime.
- Native wrappers: move sensitive parts to native code (C/C++) and protect with platform features.
- Anti-debugging / tamper checks: detect debuggers, emulators or modified binaries.
""")
    st.markdown("""### Practical tips:
1. **Never** hardcode secrets in the app bundle. Use platform keystore or server-side secrets.
2. Keep critical validation on the server-side (client-side checks can be bypassed).
3. Combine obfuscation with tamper detection and runtime integrity checks.
4. Use tooling: ProGuard/R8 for Android, Swift obfuscation tools for iOS.
""")
    add_log("Viewed Code Obfuscation guidance")

    st.markdown("""### Small demo: simple string obfuscation (XOR) and runtime deobfuscation.""")
    demo_code = textwrap.dedent('''        def xor_obfuscate(s, key=13):
            return ''.join(chr(ord(c) ^ key) for c in s)
        secret = "API_KEY=ABCDEFG12345"
        ob = xor_obfuscate(secret)
        # To reveal: xor_obfuscate(ob, 13)
    ''')
    st.code(demo_code, language='python')

    secret_input = st.text_input("Enter a short secret to obfuscate (demo):")
    obf_key = st.number_input("XOR key (integer)", min_value=1, max_value=255, value=13)
    if st.button("Obfuscate (demo)"):
        s = secret_input or "test_secret"
        ob = ''.join(chr(ord(c) ^ obf_key) for c in s)
        st.code(ob, language='text')
        st.info("This is a demo-only obfuscation. Use proper tools for production.")
        add_log("Performed demo obfuscation")

# 11. Network Monitor
elif menu == "📡 Network Monitor":
    st.subheader("📡 Network Traffic Monitor")
    p_slot = st.empty()
    t_slot = st.empty()
    for i in range(4):
        p = random.randint(50,300)
        t = random.randint(0,6)
        p_slot.metric("Packets", p)
        t_slot.metric("Suspicious", t)
        time.sleep(0.6)
    add_log("Performed Network Monitor scan")

# 12. Malware Scan
elif menu == "🧬 Malware Scan":
    st.subheader("🧬 Malware Scan")
    files_checked = random.randint(4,12)
    malware_found = random.choice([0,0,1])
    st.write(f"Files checked: {files_checked}")
    st.write(f"Malware found: {malware_found}")
    add_log("Performed Malware Scan")

# 13. Permissions Audit (interactive)
elif menu == "🔒 Permissions Audit":
    st.subheader("🔒 Permissions Audit — Interactive")
    st.write("Toggle which permissions the app currently has and click 'Analyze' to compute a risk grade.")
    col1, col2 = st.columns(2)
    with col1:
        camera = st.checkbox("Camera", value=True)
        location = st.checkbox("Location", value=False)
        storage = st.checkbox("Storage", value=True)
    with col2:
        contacts = st.checkbox("Contacts", value=True)
        microphone = st.checkbox("Microphone", value=False)
        sms = st.checkbox("SMS", value=False)

    if st.button("Analyze Permissions"):
        score = 100
        issues = []
        if camera:
            score -= 5; issues.append("Camera access")
        if contacts:
            score -= 10; issues.append("Contacts access")
        if location:
            score -= 15; issues.append("Location access")
        if microphone:
            score -= 8; issues.append("Microphone access")
        if sms:
            score -= 12; issues.append("SMS access")
        if storage:
            score -= 6; issues.append("Storage access")
        score = max(0, score)
        st.metric("Permissions Risk Score", f"{score}/100", delta=f"-{100-score}")
        st.write("Detected permission issues:")
        if issues:
            for it in issues:
                st.write(f"- {it}")
        else:
            st.write("No risky permissions detected.")
        add_log(f"Permissions Audit analyzed: {', '.join(issues) if issues else 'none'}")

# 14. AI Threat Detection
elif menu == "🤖 AI Threat Detection":
    st.subheader("🤖 AI Threat Detection")
    score, status = ai_threat_detection()
    st.write(f"Threat Score: {score}% | Status: {status}")

# 15. Device Security Check
elif menu == "📱 Device Security Check":
    st.subheader("📱 Device Security Check")
    root, integrity = device_security_check()
    st.write(f"Root Detected: {root}")
    st.write(f"Device Integrity: {integrity}")

# 16. Audit Log
elif menu == "📜 Audit Log":
    st.subheader("📜 Real-time Audit Log")
    if st.button("Clear Log"):
        st.session_state.audit_log = []
        add_log("Cleared Audit Log")
    if st.session_state.audit_log:
        df_log = pd.DataFrame(st.session_state.audit_log)
        st.table(df_log)
        csv = df_log.to_csv(index=False)
        st.download_button("Download audit log (CSV)", data=csv, file_name="audit_log.csv", mime="text/csv")
    else:
        st.info("No actions logged yet.")

# --- Footer ---
st.markdown(""" 
<style>
.footer {text-align:center; color:#00bfff; margin-top:18px; font-size:13px;}
</style>
<div class="footer">
</div>
""", unsafe_allow_html=True)
