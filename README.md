# PrivacyGuard

PrivacyGuard is a local-first hackathon demo for checking content before sharing. Its flow is **Detect → Explain → Protect**. Pattern rules detect candidate personal information; the UI explains why it matters and offers a safer copy. This is a practical demo, not a certified security product.

## Run it

Requirements: Python 3.10 or newer. Text scanning and the website UI use only the Python standard library.

```powershell
cd PrivacyGuard
python server.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). Keep the terminal open while using the app; press Ctrl+C to stop it. No Node, frontend build step, database, API key, or account is needed.

### Enable screenshot OCR and PDF extraction

Install the optional Python packages:

```powershell
python -m pip install -r requirements.txt
```

On Windows, install the OCR engine from PowerShell:

```powershell
winget install -e --id UB-Mannheim.TesseractOCR
```

Then restart PrivacyGuard and try the screenshot scan again. The server checks PATH and the standard Windows install folders. If `winget` is unavailable, use the Windows installer linked from the [official Tesseract installation guide](https://tesseract-ocr.github.io/tessdoc/Installation.html), then restart the server. If OCR is still unavailable, run `tesseract --version` in a new PowerShell window to confirm the install. Text/document scanning still works without OCR. DOCX extraction uses Python's standard library. PDF extraction uses `pypdf`.

### Demo

Select **Explore demo** on Home. It scans a synthetic sample with an `example.test` email, a fabricated payment handle, a sample address, and a clearly fake credential. No real personal details or credentials are included. Try text/file scanning, then open the Dashboard or Assistant.

## Features

- **Screenshot scanner:** PNG, JPG, and WebP up to 8 MB; OCR-based deterministic pattern matching and conservative line-level redaction. Tesseract is optional. If OCR reports a risk but cannot map it to a location, the downloaded safe copy is fully covered rather than silently left unredacted. Always review the result.
- **Text and documents:** pasted text, TXT, MD, CSV, PDF, and DOCX. Text patterns include email, phone, UPI-like handles, payment-card-like digits, transaction references, credentials/API-key-like strings, address/location-like phrases, and an identity-number-like pattern. These are pattern matches and may produce false positives or miss context.
- **Website checker:** URL normalization and validation, HTTPS, TLS verification/expiry, HTTP reachability (with a GET fallback for sites that reject HEAD), redirect count and changed-host warnings, and cautious URL-pattern signals. Connection failures are described as inconclusive and are kept distinct from URL warning scores. Local/private network destinations are blocked. No reputation or threat-intelligence service is queried. A low score, valid TLS, or successful connection does not prove a site is safe.
- **Betting website blocker:** the Website Checker stops matching keyword domains before it contacts them. A separate Chromium extension blocks matching browser navigations, has user-managed block and allow lists, and can download the maintained [HaGeZi gambling domain list](https://github.com/hagezi/dns-blocklists). The downloaded list is compared locally; visited URLs are not sent to the list provider. Lists can still miss new or unlisted betting domains and can include false positives.
- **Results:** risk score, severity, category counts, masked matches, explanation, and next steps.
- **Dashboard:** summary-only scan history held in server memory and cleared when the process stops.
- **Assistant:** a local, scan-aware explainer that answers common questions such as what to fix first, why a finding matters, and how to reduce exposure. It does not make security decisions or send content to an AI provider.

## Privacy and security notes

- The server binds to `127.0.0.1` only. It is a single-user local demo and has no login, user management, or production deployment hardening. Do not expose it to a network or deploy it publicly without adding authentication, authorization, HTTPS, rate limiting, logging controls, and deployment-specific security review.
- Uploads are limited to 8 MB, image dimensions to 20 megapixels, PDFs to 100 pages, and extracted text to 1 MB. File type is checked by extension and parser. Keep optional libraries up to date.
- Original image bytes are held in request memory; the OCR image and protected copy are created in an automatically cleaned temporary directory. Documents are parsed from memory. Originals and extracted text are not saved. The in-memory dashboard keeps only scan type, time, score, severity, and finding count.
- The assistant is a deterministic local explainer. No external AI key is used or required. If a hosted model is added later, configure its key only on the server and explicitly disclose what content is sent.
- There is no persistent database. PostgreSQL is unnecessary for this local demo; the API and scan engine are separated so persistent storage can be added later with explicit retention controls.
- No CORS access is enabled; browser API calls are same-origin. Cross-origin `Origin` headers are rejected. CSRF tokens are not configured because this local demo has no cookie-based login or authenticated state-changing actions. Add CSRF protection if authentication or cross-origin deployment is introduced.
- Website checks make outbound requests to public hosts. DNS results and redirect destinations are checked against private/local IP ranges, and requests have short timeouts. These checks do not substitute for a hardened network egress proxy in a hosted service.

## Tests

```powershell
python -m unittest discover -s tests -v
```

The tests cover deterministic detection, masking, scoring, URL validation, local-address blocking, and safe document extraction limits. The browser UI is dependency-free; use the demo flow above to walk through it.

### Install the optional browser blocker

The blocker supports Chromium-based Chrome and Edge. In Chrome open `chrome://extensions`; in Edge open `edge://extensions`. Turn on **Developer mode**, choose **Load unpacked**, and select the project's `browser-blocker` folder. Open its toolbar popup and choose **Update list** to fetch the maintained list once; use that button again to refresh it later. Keep the blocker enabled. Its settings page lets you add domains to block and exceptions to allow. It checks hostnames locally; it does not inspect page contents. The browser asks permission to apply it to websites you visit. Use `https://casino.example.com` as a synthetic blocked-page demo without visiting a real betting site.

## Configuration

Set `PORT` to a different local port if needed (default `8000`):

```powershell
$env:PORT = "8080"
python server.py
```

Only bind to localhost for this demo. There are no secrets or `.env` values to configure.
