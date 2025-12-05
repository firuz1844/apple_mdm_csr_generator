import os
import sys
import subprocess
import tempfile
import getpass
import base64
# import shutil

OPENSSL_BIN = "/usr/bin/openssl"

def main():
    # Check command-line arguments
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <CertAndKkeyFile.p12>")
        sys.exit(1)
    key_p12 = sys.argv[1]

    # Validate input file
    if not os.path.isfile(key_p12):
        print(f"Key file not found: {key_p12}")
        sys.exit(1)

    # Ask for PKCS#12 password
    try:
        p12_password = getpass.getpass(f"Enter password for {key_p12}: ")
    except Exception as e:
        print(f"Password input error: {e}")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        generated_key_path = os.path.join(script_dir, "csr_private_key.pem")
    except Exception as e:
        print(f"Failed to create key file: {e}")
        sys.exit(1)

    # Create temporary files for key, certificate and configuration
    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp(prefix="mdmcsr_")
        key_pem_path = os.path.join(temp_dir, "extracted_key.pem")
        cert_pem_path = os.path.join(temp_dir, "extracted_cert.pem")
        vendor_pem_path = os.path.join(temp_dir, "vendor.pem")
        wwdr_cer_path = os.path.join(os.getcwd(), "AppleWWDRCAG3.cer")
        apple_root_cer_path = os.path.join(os.getcwd(), "AppleIncRootCertificate.cer")
        wwdr_pem_path = os.path.join(temp_dir, "AppleWWDRCAG3.pem")
        apple_root_pem_path = os.path.join(temp_dir, "AppleIncRootCertificate.pem")
        csr_conf_path = os.path.join(temp_dir, "csr.conf")
        csr_pem_path = os.path.join(temp_dir, "request.csr.pem")
        csr_der_path = os.path.join(temp_dir, "request.csr.der")
        csr_sig_path = os.path.join(temp_dir, "request.csr.der.sig")
        combined_chain_pem_path = os.path.join(temp_dir, "combined_chain.pem")
    except Exception as e:
        print(f"Failed to create temporary directory: {e}")
        sys.exit(1)

    try:
        # 1. Extract private key from PKCS#12 (without encrypting the output)
        cmd = [
            OPENSSL_BIN, "pkcs12",
            "-in", key_p12,
            "-nocerts",      # do not extract certificates, only key
            "-nodes",        # do not encrypt key
            "-out", key_pem_path,
            "-passin", f"pass:{p12_password}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print("Error extracting private key from PKCS#12:")
            print(result.stderr.strip() or "Unknown error")
            sys.exit(1)

        # 1a. Extract certificate from PKCS#12 (optional, in case needed)
        cmd = [
            OPENSSL_BIN, "pkcs12",
            "-in", key_p12,
            "-clcerts",   # extract only client certificate
            "-nokeys",    # do not extract key
            "-out", cert_pem_path,
            "-passin", f"pass:{p12_password}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print("Error extracting certificate from PKCS#12:")
            print(result.stderr.strip() or "Unknown error")
            sys.exit(1)

        # Verify that the extracted certificate file looks valid
        try:
            with open(cert_pem_path, "r") as cert_f:
                cert_content = cert_f.read()
            if "-----BEGIN CERTIFICATE-----" not in cert_content:
                print("Error: no valid certificate found in PKCS#12 (missing certificate data).")
                sys.exit(1)
        except Exception as e:
            print(f"Error reading extracted certificate from PKCS#12: {e}")
            sys.exit(1)

        # Additionally attempt to include Apple WWDR intermediate and Apple Root certificate
        # Start chain with the certificate extracted from PKCS#12
        chain_paths = [cert_pem_path]

        # Apple WWDR intermediate certificate
        if os.path.isfile(wwdr_cer_path):
            try:
                with open(wwdr_cer_path, "rb") as f_in:
                    header = f_in.read(30)
                    is_binary = any(byte > 127 or byte < 32 for byte in header) and not header.startswith(b"-----BEGIN")
                if is_binary:
                    cmd = [
                        OPENSSL_BIN, "x509",
                        "-inform", "der",
                        "-in", wwdr_cer_path,
                        "-out", wwdr_pem_path,
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode != 0:
                        print("Warning: failed to convert AppleWWDRCAG3.cer to PEM format:")
                        print(result.stderr.strip() or "Unknown error")
                    else:
                        chain_paths.append(wwdr_pem_path)
                else:
                    with open(wwdr_cer_path, "rb") as src, open(wwdr_pem_path, "wb") as dst:
                        dst.write(src.read())
                    chain_paths.append(wwdr_pem_path)
            except Exception as e:
                print(f"Warning: error processing WWDR certificate: {e}")
        else:
            print("Warning: AppleWWDRCAG3.cer not found in current directory. Certificate chain may be incomplete.")

        # Apple root certificate
        if os.path.isfile(apple_root_cer_path):
            try:
                with open(apple_root_cer_path, "rb") as f_in:
                    header = f_in.read(30)
                    is_binary = any(byte > 127 or byte < 32 for byte in header) and not header.startswith(b"-----BEGIN")
                if is_binary:
                    cmd = [
                        OPENSSL_BIN, "x509",
                        "-inform", "der",
                        "-in", apple_root_cer_path,
                        "-out", apple_root_pem_path,
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode != 0:
                        print("Warning: failed to convert AppleIncRootCertificate.cer to PEM format:")
                        print(result.stderr.strip() or "Unknown error")
                    else:
                        chain_paths.append(apple_root_pem_path)
                else:
                    with open(apple_root_cer_path, "rb") as src, open(apple_root_pem_path, "wb") as dst:
                        dst.write(src.read())
                    chain_paths.append(apple_root_pem_path)
            except Exception as e:
                print(f"Warning: error processing Apple root certificate: {e}")
        else:
            print("Warning: AppleIncRootCertificate.cer not found in current directory. Certificate chain may be incomplete.")

        # Combine all certificates into a single PEM chain file
        try:
            with open(combined_chain_pem_path, "w") as out_f:
                for p in chain_paths:
                    with open(p, "r") as in_f:
                        out_f.write(in_f.read().rstrip())
                        out_f.write("\n")
        except Exception as e:
            print(f"Error building combined certificate chain: {e}")
            sys.exit(1)

        # 3. Create CSR configuration file
        try:
            print("Enter CSR subject fields:")
            subj_fields = {
                "C": "Country Name (2 letters) [C]: ",
                "ST": "State or Province Name [ST]: ",
                "L": "Locality Name (City) [L]: ",
                "O": "Organization Name [O]: ",
                "OU": "Organizational Unit Name [OU]: ",
                "CN": "Common Name (e.g. company or server name) [CN]: "
            }
            dn_lines = []
            for field, prompt_text in subj_fields.items():
                # Ask user to input field value
                value = input(prompt_text).strip()
                if value:
                    dn_lines.append(f"{field} = {value}")
            # Write configuration file
            with open(csr_conf_path, "w") as conf:
                conf.write("[req]\n")
                conf.write("prompt = no\n")
                conf.write("distinguished_name = req_distinguished_name\n")
                conf.write("\n[req_distinguished_name]\n")
                if dn_lines:
                    for line in dn_lines:
                        conf.write(line + "\n")
        except Exception as e:
            print(f"I/O error while creating CSR configuration: {e}")
            sys.exit(1)

        # 4. Generate CSR (PEM) with openssl
        ## 4.1 Generate private key
        print("Generating key...")
        cmd = [
            OPENSSL_BIN, "genrsa",
            "-out", generated_key_path,
            "2048",
        ]
        print(cmd)
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print("Error generating key with openssl:")
            print(result.stderr.strip() or "Unknown error")
            sys.exit(1)
        else:
            # dest_key_path = os.path.join(script_dir, "new_key.pem")
            # shutil.copy(generated_key_path, dest_key_path)

            print(result.stdout)

        ## 4.2. Creating CSR
        cmd = [
            OPENSSL_BIN, "req", "-new",
            "-key", generated_key_path,
            "-out", csr_pem_path,
            "-config", csr_conf_path,
            "-sha256",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print("Error generating CSR with openssl:")
            print(result.stderr.strip() or "Unknown error")
            sys.exit(1)

        # Convert PEM CSR to DER
        cmd = [
            OPENSSL_BIN, "req",
            "-inform", "PEM",
            "-outform", "DER",
            "-in", csr_pem_path,
            "-out", csr_der_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print("Error converting CSR to DER format:")
            print(result.stderr.strip() or "Unknown error")
            sys.exit(1)

        # Sign DER CSR with vendor private key using SHA1 (as in Apple examples)
        print("Signing CSR...")
        cmd = [
            OPENSSL_BIN, "sha1", "-sign", key_pem_path,
            "-out", csr_sig_path,
            csr_der_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print("Error signing CSR with openssl:")
            print(result.stderr.strip() or "Unknown error")
            sys.exit(1)

        # Read and base64-encode CSR (DER), signature, and certificate chain
        try:
            with open(csr_der_path, "rb") as f:
                csr_der_b64 = base64.b64encode(f.read()).decode("ascii")
            with open(csr_sig_path, "rb") as f:
                sig_b64 = base64.b64encode(f.read()).decode("ascii")
            with open(combined_chain_pem_path, "r") as f:
                vendor_chain = f.read().rstrip()
        except Exception as e:
            print(f"Error reading CSR/signature/certificate chain: {e}")
            sys.exit(1)

        # Build plist in Apple MDM Push Certificate Request format
        plist_xml = f'''<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n    <key>PushCertRequestCSR</key>\n    <string>{csr_der_b64}</string>\n    <key>PushCertCertificateChain</key>\n    <string>\n{vendor_chain}\n</string>\n    <key>PushCertSignature</key>\n    <string>{sig_b64}</string>\n</dict>\n</plist>\n'''

        try:
            with open("request.plist", "w", encoding="utf-8") as f:
                f.write(plist_xml)
        except Exception as e:
            print(f"Error writing PushCertificateRequest.plist: {e}")
            sys.exit(1)

        # Base64-encode the entire plist
        try:
            plist_b64 = base64.b64encode(plist_xml.encode("utf-8")).decode("ascii")
            # base64 plist for uploading to Apple
            with open("request.csr", "w", encoding="utf-8") as f:
                f.write(plist_b64)
        except Exception as e:
            print(f"Error writing base64 files: {e}")
            sys.exit(1)

        print("\nFiles 'request.plist' and 'request.csr' have been created.")
        print("File 'request.csr' contains the same data as in plist but base64 encoded. It is ready for uploading to the Apple portal by customer on http://identity.apple.com/pushcert/.")

    finally:
        # Remove only temporary files that were created
        for tmp_path in [key_pem_path, cert_pem_path, vendor_pem_path, wwdr_pem_path, apple_root_pem_path, combined_chain_pem_path, csr_conf_path, csr_pem_path, csr_der_path, csr_sig_path]:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
        if temp_dir and os.path.isdir(temp_dir):
            try:
                os.rmdir(temp_dir)
            except OSError:
                pass

if __name__ == "__main__":
    main()
