# Apple MDM CSR Generator

A Python script for generating the **Apple MDM Vendor–side CSR** for your MDM customers.
The script produces the special plist format required by Apple and prepares it for upload to the Apple Push Certificates Portal.

Based on Apple's official documentation:
https://developer.apple.com/documentation/devicemanagement/setting-up-push-notifications-for-your-mdm-customers#Sign-the-CSR

---

## What the script does

The script:

1. Extracts the **private key** and **MDM Vendor certificate** from your **`mdm.p12`** (exported from Keychain Access).
2. Builds the full certificate chain:
   - Your MDM Vendor Certificate (from `key.p12`)  
   - Apple WWDR Intermediate (`AppleWWDRCAG3.cer`)  
   - Apple Root Certificate (`AppleIncRootCertificate.cer`)  
3. Generates a customer CSR (PEM → DER).
4. Signs the DER CSR using your Vendor key (SHA1), as required by Apple.
5. Creates a plist of the form:

   ```xml
   <key>PushCertRequestCSR</key>
   <string>…base64(DER CSR)…</string>
   <key>PushCertCertificateChain</key>
   <string>
   -----BEGIN CERTIFICATE-----
   ...
   -----END CERTIFICATE-----
   </string>
   <key>PushCertSignature</key>
   <string>…base64(signature)…</string>
   ```

8. Encodes the plist in base64 for upload to the Apple Push Certificates Portal.

---

## Requirements

- macOS  
- Built‑in **Python 3**
- Built‑in **/usr/bin/openssl (LibreSSL)**  
- Your valid **Apple MDM Vendor certificate**:
  - `key.p12` (contains both the vendor certificate and private key, exported from Keychain Access + password you are enetered while export)
- Apple certificate authority files:
  - https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer  
  - http://www.apple.com/appleca/AppleIncRootCertificate.cer  

---

## Folder layout

Place all files in a single directory:

```
mdm_scr/
├── mdm_csr.py
├── mdm.p12
├── AppleWWDRCAG3.cer
└── AppleIncRootCertificate.cer
```

---

## Usage

```bash
cd /path/to/mdm_scr
python3 mdm_csr.py mdm.p12
```

The script will:

1. Ask for the password of `mdm.p12`.
2. Ask for CSR subject fields: C, ST, L, O, OU, CN.

After successful execution you will get:

- **PushCertificateRequest.plist** — final plist required by Apple  
- **PushCertificateRequest.plist.base64** — base64‑encoded plist  
- **request.csr** — same base64 plist, convenient for portal upload  

Upload `request.csr` or `PushCertificateRequest.plist.base64` to:  
https://identity.apple.com/pushcert/

---

## ⚠️ Important

If WWDR or Root certificates are missing, the script will warn you and produce an incomplete chain.  
In that case, the Apple portal will reject the request with:

❌ **Invalid Certificate Signing Request**  
❌ **Signing Certificate Chain Missing**

- The script also validates that the PKCS#12 actually contains a certificate.  
  If no valid certificate is found, it will exit with an error:
  `Error: no valid certificate found in PKCS#12 (missing BEGIN CERTIFICATE).`

---
