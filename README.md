# Veil Agent — Privacy-Preserving Smart Form Autofill

> **Zero PII Leakage • On-Device Encrypted Vault • Safe Form Autofill with Review-Before-Submit**

Veil Agent is an on-device, privacy-preserving browser extension that automates filling web forms (Google Forms, Job Applications, Government Portals, Signups, KYC) directly from your personal encrypted vault without any external servers or complex model downloads.

---

## 🚀 The Pipeline Flow

```text
One-time setup:  You → fill vault with all your details
                        ↓
Every form:      Agent reads form → matches fields to vault keys → fills automatically
                        ↓
                 Password/Aadhaar/PAN → skipped (sensitive)
                 Submit → asks for approval
```

1. **One-Time Setup (`My Vault`)**:
   Enter every personal, contact, address, education, and career detail once. All details are encrypted on-device using WebCrypto (`AES-GCM` 256-bit with PBKDF2) and stored locally.
2. **Every Form**:
   Agent scans the web form, extracts questions and field titles (including Google Forms, React SPAs, and standard HTML5), matches them against your Vault keys, and fills them automatically.
3. **Sensitive Fields Skipped**:
   High-risk credentials (`Password`, `Aadhaar`, `PAN`, `SSN`, `Card Number`, `CVV`, `OTP`) are **strictly skipped** and left untouched for maximum security.
4. **Submit Asks for Approval**:
   The agent **never** automatically submits forms. When all fields are filled, it generates an interactive review card in the popup showing all filled fields and skipped sensitive fields, requiring your explicit **"Approve & Submit"** before clicking the form's submit button.

---

## 📦 How to Install and Run in Google Chrome

1. Open Google Chrome.
2. Navigate to `chrome://extensions/`.
3. Enable **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked**.
5. Select the `veil/extension` directory:
   ```
   d:\downloads\Downloads\veil-skeleton\veil\extension
   ```
6. Pin **Veil Agent** to your Chrome toolbar.

---

## 💡 How to Use

### 1. Fill Your Vault (One-Time Setup)
1. Click the **Veil Agent** icon in Chrome.
2. Open the **🔐 My Vault (One-Time Setup)** tab.
3. Fill in your details (or click **📋 Demo Data** to populate sample data).
4. Click **💾 Save Vault**.

### 2. Autofill Any Form
1. Open any web form in your browser (e.g. Google Forms, job portal, signup page).
2. Click the **Veil Agent** icon.
3. Click **⚡ Auto-Fill This Form**.
4. Watch the agent detect, match, and fill all fields in real-time.
5. Review the summary in the popup and click **🚀 Approve & Submit Form** to finalize.

---

## 🛡️ Security & Privacy Invariants

- **100% Local Execution**: Runs entirely in your browser using Chrome Extension APIs. Zero external servers required.
- **Zero Network Egress**: Your personal data never leaves your device.
- **Sensitive Credentials Protected**: Password, Aadhaar, and PAN inputs are strictly bypassed and never filled automatically.
- **User in Full Control**: Form submissions always require explicit user review and approval.
