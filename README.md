# Apple MDM CSR Generator

A Python script for manual generating the **Apple MDM Vendor–side CSR** for your MDM customers.
The script produces the special plist format required by Apple and prepares it for upload to the Apple Push Certificates Portal.

Based on Apple's official documentation:
https://developer.apple.com/documentation/devicemanagement/setting-up-push-notifications-for-your-mdm-customers#Sign-the-CSR

---

## What the script does

The script:

1. Extracts the **private key** and **MDM Vendor certificate** from your **`CertAndKeyFile.p12`** (exported from Keychain Access).
2. Builds the full certificate chain:
   - Your MDM Vendor Certificate (extracted from provided p12 container)
   - Apple WWDR Intermediate (`AppleWWDRCAG3.cer`)
   - Apple Root Certificate (`AppleIncRootCertificate.cer`)
3. Generates a customer CSR based on new Customer private key (PEM → DER).
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
  - `CertAndKeyFile.p12` (contains both the vendor certificate and private key, exported from Keychain Access + password you are enetered while export)
- Apple certificate authority files:
  - https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer
  - http://www.apple.com/appleca/AppleIncRootCertificate.cer

---

## Usage

1. Download and put Apple's root certificates to folder with script (AppleWWDRCAG3.cer and AppleIncRootCertificate.cer).
2. Export and put to the same folder private key and vendor certificate from Keychain Acces on the computer, where Vendor CSR was generated to p12 container
```
/path/to/mdm_csr/
├── mdm_csr.py
├── CertAndKeyFile.p12 (yor Vendor Cert and Private key exported from Keychain Access)
├── AppleWWDRCAG3.cer
└── AppleIncRootCertificate.cer
```
3. Run script and provide Customer's Organisation Country, Name, Address etc

```bash
cd /path/to/mdm_csr
python3 mdm_csr.py CertAndKeyFile.p12
```

The script will:

- Ask for the password of `CertAndKeyFile.p12`.
- Ask for CSR subject fields: C, ST, L, O, OU, CN.

After successful execution you will get in the same folder:

- **csr_private_key.pem** — a new private key generated while creating the CSR request.
- **request.csr** — base64 encoded plist, for portal upload

```
/path/to/mdm_csr/
├── ...
├── csr_private_key.pem (Keep this private key)
└── request.csr (Send this file to customer)
```

Done!

Provide the `request.csr` file to your MDM customer so they can upload it to:
https://identity.apple.com/pushcert/

After customer creates certificate, they give it back to you. You will need both the new certificate and csr_private_key.pem for sending MDM commands to customer's devices.

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
