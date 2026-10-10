"""PrivacyGuard local demo API. No originals are persisted; history stores summaries only."""
from __future__ import annotations

import base64
import io
import json
import mimetypes
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parent
APP_BUILD = "ocr-tsv-float-20261007"
MAX_BODY = 12 * 1024 * 1024
HISTORY = []
LOCK = threading.Lock()

RULES = [
    ("Email", "Contact", 18, re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "An email address can expose your identity or invite unwanted contact."),
    ("Phone number", "Contact", 20, re.compile(r"(?<!\w)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\w)|(?<!\w)\+?\d[\d ()-]{8,}\d(?!\w)"), "A phone number can be used for spam, scams, or unwanted contact."),
    ("UPI ID", "Financial", 24, re.compile(r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z][a-zA-Z0-9.-]{1,}\b"), "A payment handle can identify your financial account."),
    ("Payment card", "Financial", 30, re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "Payment card-like digits should not be shared publicly."),
    ("Transaction reference", "Financial", 23, re.compile(r"\b(?:txn|transaction|upi\s*ref|utr|reference|order\s*id)\s*[:#-]?\s*[A-Z0-9-]{6,}\b", re.I), "A transaction reference may expose private payment activity."),
    ("Credential / secret", "Credentials", 35, re.compile(r"(?i)\b(?:password|passwd|api[_ -]?key|access[_ -]?token|secret|authorization)\b\s*[:=]\s*['\"]?[^\s'\"]{6,}"), "A credential or key could grant access to an account or service."),
    ("API key pattern", "Credentials", 35, re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b"), "This resembles a service credential. Revoke it if it was real."),
    ("Address / location", "Location", 18, re.compile(r"(?i)\b(?:\d{1,5}\s+[\w .'-]{2,40}\s(?:street|st|road|rd|avenue|ave|lane|ln|drive|dr|nagar|colony|apartment|apt)\b|(?:latitude|longitude|gps|coordinates|location)\s*[:=]\s*-?\d{1,3}\.\d{3,})"), "A street address or precise location can reveal where you live or travel."),
    ("Government ID pattern", "Identity", 26, re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"), "This resembles a national identity number. Confirm before sharing."),
]

BETTING_DOMAIN_TERMS = ("bet", "betting", "xbet", "casino", "gambling", "poker", "sportsbook", "bookmaker", "wager", "rummy")

ASSISTANT_ADVICE = {
    "Email": "Remove it or replace it with a separate public contact address.",
    "Phone number": "Remove it or hide all but the last few digits.",
    "UPI ID": "Remove the payment handle from anything you plan to post publicly.",
    "Payment card": "Do not share the number. If it is real and exposed, contact your card issuer.",
    "Transaction reference": "Remove the reference; it can reveal payment activity or help someone impersonate support.",
    "Credential / secret": "Do not share it. If it is real, revoke or rotate it with the service that issued it.",
    "API key pattern": "Do not share it. Revoke or rotate the key at its provider if it is real.",
    "Address / location": "Remove the address or precise coordinates, especially from public posts.",
    "Government ID pattern": "Keep it private. Verify what it is before sharing it with a trusted recipient.",
}

def assistant_reply(question, findings):
    """Give scan-grounded guidance without treating the assistant as a detector."""
    question = str(question or "").strip().lower()
    if len(question) > 1000:
        question = question[:1000]

    by_type = {}
    for finding in findings[:30]:
        if not isinstance(finding, dict):
            continue
        label = str(finding.get("type", "finding"))[:80]
        if label not in by_type:
            by_type[label] = {
                "category": str(finding.get("category", "Privacy"))[:40],
                "severity": str(finding.get("severity", "review"))[:20],
                "explanation": str(finding.get("explanation", "Review this detected pattern."))[:240],
            }

    if not by_type:
        opening = "I don't have any findings from a completed scan to explain yet. Run a text, document, or image scan first."
        if any(term in question for term in ("share", "safe", "post")):
            opening += " A clean result is not proof that content is safe; review the full content and its context before sharing."
        return opening + " I explain scanner results; I do not independently inspect or certify content."

    types = list(by_type)
    if any(term in question for term in ("first", "priority", "fix", "start")):
        ordered = sorted(types, key=lambda label: (0 if by_type[label]["severity"] == "critical" else 1, -next((rule[2] for rule in RULES if rule[0] == label), 0)))
        lead = ordered[0]
        answer = f"Start with {lead}: {ASSISTANT_ADVICE.get(lead, 'Review and remove it if it is not needed.') }"
        if len(ordered) > 1:
            answer += " Then review " + ", ".join(ordered[1:]) + "."
    elif any(term in question for term in ("share", "post", "public", "safe")):
        answer = "I would review this before sharing: the scan found " + ", ".join(types) + "."
        answer += " Remove or redact those details, then inspect the protected copy yourself."
    elif any(term in question for term in ("why", "what", "explain", "mean", "detected")):
        details = [f"{label} ({by_type[label]['category']}): {by_type[label]['explanation']}" for label in types]
        answer = "The scan matched these patterns: " + " ".join(details)
    elif any(term in question for term in ("how", "protect", "remove", "hide", "redact")):
        answer = "Suggested actions: " + " ".join(f"{label}: {ASSISTANT_ADVICE.get(label, 'Review and remove it if it is not needed.')}" for label in types)
    else:
        answer = "Your latest scan found " + ", ".join(types) + ". Ask what to fix first, why a finding matters, or how to reduce exposure."

    return answer + " The scanner uses deterministic pattern rules; results can be wrong or incomplete, and I cannot certify that content is safe."

def scan_text(text: str):
    found = []
    for label, category, weight, regex, why in RULES:
        for m in regex.finditer(text):
            value = m.group(0)
            # Avoid classifying an email as a UPI handle.
            if label == "UPI ID" and "." in value.split("@")[-1]:
                continue
            found.append({"type": label, "category": category, "start": m.start(), "end": m.end(), "masked": mask(value), "severity": "critical" if weight >= 30 else "high" if weight >= 22 else "medium", "explanation": why, "weight": weight})
    # When broad patterns overlap a more specific signal (e.g. a card number
    # also looks like a phone), keep the higher-risk specific match first.
    found.sort(key=lambda f: (f["start"], -f["weight"], -(f["end"] - f["start"])))
    # Keep overlapping matches from obscuring one another.
    unique = []
    for item in found:
        if any(item["start"] < old["end"] and item["end"] > old["start"] for old in unique):
            continue
        unique.append(item)
    score = min(100, sum(x["weight"] for x in unique))
    return {"findings": unique, "score": score, "level": "Low" if score < 20 else "Moderate" if score < 45 else "High" if score < 70 else "Critical", "categories": {c: sum(1 for x in unique if x["category"] == c) for c in ["Contact", "Financial", "Credentials", "Location", "Identity"]}, "recommendations": list(dict.fromkeys(x["explanation"] for x in unique)) or ["No matching patterns were detected. Automated scans can miss context; review your content before sharing."]}

def mask(value):
    return "•" * max(4, len(value) - min(4, len(value))) + value[-min(4, len(value)):]

def find_tesseract():
    candidates = [shutil.which("tesseract"), os.environ.get("TESSERACT_CMD")]
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidates.extend([
        str(Path(program_files) / "Tesseract-OCR" / "tesseract.exe"),
        str(Path(program_files_x86) / "Tesseract-OCR" / "tesseract.exe"),
        str(Path(local_app_data) / "Programs" / "Tesseract-OCR" / "tesseract.exe") if local_app_data else None,
    ])
    if os.name == "nt":
        try:
            import winreg
            for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                for key_path in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\tesseract.exe", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\tesseract.exe"):
                    try:
                        with winreg.OpenKey(hive, key_path) as key:
                            candidates.append(winreg.QueryValue(key, None))
                    except OSError:
                        pass
        except ImportError:
            pass
    return next((str(Path(candidate)) for candidate in candidates if candidate and Path(candidate).is_file()), None)

def remember(kind, score, count, level):
    with LOCK:
        HISTORY.insert(0, {"id": secrets.token_hex(5), "kind": kind, "score": score, "count": count, "level": level, "at": datetime.now(timezone.utc).isoformat()})
        del HISTORY[100:]

def safe_resolve(host):
    if host.lower() in {"localhost", "localhost.localdomain"}:
        raise ValueError("Local and private network addresses are not checked.")
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("Could not find this domain. Check the spelling and try again.") from exc
    if not infos:
        raise ValueError("Could not find this domain. Check the spelling and try again.")
    for info in infos:
        ip = info[4][0]
        addr = __import__('ipaddress').ip_address(ip)
        if not addr.is_global:
            raise ValueError("Local and private network addresses are not checked.")

def normalize_url(raw):
    raw = str(raw or "").strip()
    if not raw: raise ValueError("Enter a website address, such as example.com.")
    if len(raw) > 2048: raise ValueError("URL is too long (maximum 2,048 characters).")
    if any(ord(char) < 32 or char.isspace() for char in raw):
        raise ValueError("Remove spaces and control characters from the URL.")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = "https://" + raw
    try:
        parsed = urllib.parse.urlsplit(raw)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The URL has an invalid host or port.") from exc
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Use a website URL that starts with http:// or https://.")
    if not hostname or parsed.username or parsed.password:
        raise ValueError("Enter a valid public website URL without embedded credentials.")
    try:
        ascii_host = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        import ipaddress
        is_ip = False
        try:
            ipaddress.ip_address(ascii_host)
            is_ip = True
        except ValueError:
            pass
        if not is_ip:
            labels = ascii_host.split(".")
            if len(labels) < 2 or len(ascii_host) > 253 or any(
                not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                for label in labels
            ):
                raise ValueError("Enter a full public domain, such as example.com.")
        hostport = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
        netloc = hostport + (f":{port}" if port is not None else "")
        return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
    except UnicodeError as exc:
        raise ValueError("The domain name is not valid.") from exc

def extract_document(name, raw):
    ext = Path(name).suffix.lower()
    if ext not in {".txt", ".md", ".csv", ".pdf", ".docx"}: raise ValueError("Choose a TXT, MD, CSV, PDF, or DOCX file.")
    if not raw or len(raw) > 8 * 1024 * 1024: raise ValueError("File is empty or exceeds the 8 MB limit.")
    if ext in {".txt", ".md", ".csv"}: content = raw.decode("utf-8-sig")
    elif ext == ".pdf":
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(raw), strict=True)
        if len(reader.pages) > 100: raise ValueError("PDF exceeds the 100 page limit.")
        content = "\n".join(page.extract_text() or "" for page in reader.pages)
    else:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if "word/document.xml" not in archive.namelist() or len(archive.namelist()) > 200: raise ValueError("This is not a supported DOCX document.")
            if sum(item.file_size for item in archive.infolist()) > 32 * 1024 * 1024: raise ValueError("DOCX expands beyond the 32 MB processing limit.")
            root = ET.fromstring(archive.read("word/document.xml"))
            content = "\n".join(node.text or "" for node in root.iter() if node.tag.endswith("}t"))
    if len(content) > 1_000_000: raise ValueError("Extracted text exceeds the 1 MB limit.")
    return content

def parse_ocr_tsv(tsv):
    lines = {}
    for row in tsv.splitlines()[1:]:
        cols = row.split("\t")
        try:
            if len(cols) >= 12 and cols[11].strip() and float(cols[10] or 0) > 0:
                key = tuple(cols[:5])
                lines.setdefault(key, []).append((cols[11], *(int(x) for x in cols[6:10])))
        except ValueError:
            continue
    return lines

class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Redirect target is not a valid web URL.")
        safe_resolve(parsed.hostname)
        self.count += 1
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def check_url(raw):
    raw = normalize_url(raw)
    p = urllib.parse.urlsplit(raw)
    host_labels = p.hostname.lower().rstrip(".").split(".")
    host_tokens = [token for label in host_labels for token in re.split(r"[^a-z]+", label) if token]
    betting_terms = [term for term in BETTING_DOMAIN_TERMS if term in host_tokens]
    if betting_terms:
        return {
            "url": raw, "https": p.scheme == "https", "flags": [{"title": "Betting or gambling domain keyword", "explanation": "The host name contains a betting-related keyword. This is a local category filter, not proof of a scam or malware."}],
            "redirects": 0, "reachable": None, "tls": None, "httpStatus": None,
            "note": "PrivacyGuard did not contact this domain. The keyword filter can miss betting sites with unrelated names and can match unrelated sites.",
            "score": 75, "level": "High", "summary": "Blocked by local betting-site filter", "blocked": True,
            "recommendations": ["This URL was stopped before a network request was made.", "The category is inferred from the host name only; verify the site independently if you believe this is a mistake."],
        }
    safe_resolve(p.hostname)
    flags = []
    if p.scheme != "https": flags.append(("Connection is not HTTPS", 25, "Information sent to this site may not be encrypted in transit."))
    hostname = p.hostname.lower().rstrip(".")
    try:
        import ipaddress
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False
    if hostname.startswith("xn--") or ".xn--" in hostname:
        flags.append(("Internationalized domain", 18, "This domain uses encoded non-Latin characters. Check each character and the spelling carefully."))
    if hostname.count("-") >= 3 or is_ip:
        flags.append(("Unusual domain format", 15, "The host uses a numeric address or several hyphens; verify that this is the destination you intended."))
    if len(hostname) > 55:
        flags.append(("Unusual URL structure", 12, "This unusually long host can make the destination harder to recognize."))
    if any(k.lower() in {"redirect", "url", "next", "return", "continue", "dest"} for k, _ in urllib.parse.parse_qsl(p.query)):
        flags.append(("Redirect parameter", 12, "The URL includes a parameter that may send visitors elsewhere."))
    if len(p.query) > 140 or len(p.path) > 120: flags.append(("Long URL", 8, "Long URLs can obscure the final destination."))
    if re.search(r"(?i)(login|verify|wallet|secure|account|password).{0,20}(update|confirm|unlock|urgent)", p.path + "?" + p.query): flags.append(("Sensitive-action wording", 18, "The URL contains wording often used to prompt account actions; verify the destination independently."))
    result = {"url": raw, "https": p.scheme == "https", "flags": [{"title": t, "explanation": e} for t, _, e in flags], "redirects": 0, "reachable": None, "tls": None, "httpStatus": None, "note": "These checks describe URL format and the connection only. They do not check reputation, page content, or malware."}
    opener = urllib.request.build_opener(SafeRedirect())
    redirect_handler = next((h for h in opener.handlers if isinstance(h, SafeRedirect)), None)
    try:
        req = urllib.request.Request(raw, headers={"User-Agent": "PrivacyGuard/1.0 (local safety check)"}, method="HEAD")
        with opener.open(req, timeout=5) as response:
            result["reachable"] = True
            result["httpStatus"] = response.status
            result["finalUrl"] = response.geturl()
    except urllib.error.HTTPError as exc:
        if exc.code in (405, 501):
            try:
                request = urllib.request.Request(raw, headers={"User-Agent": "PrivacyGuard/1.0 (local safety check)", "Range": "bytes=0-0"})
                with opener.open(request, timeout=5) as response:
                    response.read(1)
                    result["reachable"] = True
                    result["httpStatus"] = response.status
                    result["finalUrl"] = response.geturl()
            except urllib.error.HTTPError as fallback:
                result["reachable"] = True
                result["httpStatus"] = fallback.code
                result["finalUrl"] = fallback.geturl()
            except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                result["reachable"] = False
        else:
            # An HTTP error response still proves that the host answered.
            result["reachable"] = True
            result["httpStatus"] = exc.code
            result["finalUrl"] = exc.geturl()
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        result["reachable"] = False
        reason = getattr(exc, "reason", exc)
        result["connectionNote"] = "The connection could not be confirmed (" + ("DNS lookup failed" if isinstance(reason, socket.gaierror) else "timeout" if isinstance(reason, (TimeoutError, socket.timeout)) else "network or server response issue") + "). This alone does not mean the site is unsafe."
    result["redirects"] = redirect_handler.count if redirect_handler else 0
    result["redirectTarget"] = urllib.parse.urlsplit(result.get("finalUrl", raw)).hostname
    if result["redirects"] and result["redirectTarget"] and result["redirectTarget"].lower().rstrip(".") != p.hostname.lower().rstrip("."):
        flags.append(("Redirect changed the host", 12, "The address ended at a different host. Confirm that the final domain is the one you expected."))
    if p.scheme == "https":
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((p.hostname, p.port or 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=p.hostname) as tls_sock:
                    result["tls"] = {"valid": True, "expires": datetime.fromtimestamp(ssl.cert_time_to_seconds(tls_sock.getpeercert()["notAfter"]), timezone.utc).date().isoformat()}
        except ssl.SSLCertVerificationError:
            result["tls"] = {"valid": False}
            flags.append(("TLS certificate validation failed", 20, "The certificate presented by this server could not be validated. Avoid entering sensitive information until you verify the correct site address."))
        except (OSError, ssl.SSLError, TimeoutError):
            result["tls"] = {"valid": None}
            result["tlsNote"] = "TLS could not be checked because the server did not complete a connection. This is inconclusive, not proof of a bad certificate."
    score = min(100, sum(w for _, w, _ in flags))
    result["flags"] = [{"title": t, "explanation": e} for t, _, e in flags]
    result["score"] = score
    result["level"] = "Low" if score < 20 else "Moderate" if score < 45 else "High" if score < 70 else "Critical"
    result["summary"] = "Could not confirm a connection" if result["reachable"] is False and score == 0 else "Review URL and connection signals" if score else "No obvious URL-format concerns found"
    result["recommendations"] = [e for _, _, e in flags] or ([result["connectionNote"]] if result.get("connectionNote") else []) or ["No obvious URL-format concerns were detected. Confirm the domain spelling before entering sensitive information."]
    return result

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_OPTIONS(self): self.send_error(405)
    def send_json(self, data, status=200):
        raw = json.dumps(data).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(raw))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        if self.path == "/api/history":
            with LOCK: self.send_json({"scans": HISTORY})
        elif self.path == "/api/health":
            tesseract = find_tesseract()
            self.send_json({"ok": True, "build": APP_BUILD, "ocr": bool(tesseract), "ocrPath": tesseract})
        else:
            path = ROOT / ("index.html" if self.path in ("/", "/index.html") else self.path.lstrip("/"))
            if not path.resolve().is_relative_to(ROOT.resolve()) or not path.is_file(): self.send_error(404); return
            data = path.read_bytes(); self.send_response(200); self.send_header("Content-Type", mimetypes.guess_type(str(path))[0] or "application/octet-stream"); self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        try:
            origin = self.headers.get("Origin")
            if origin and urllib.parse.urlsplit(origin).netloc != self.headers.get("Host", ""):
                self.send_json({"error": "Cross-origin requests are not allowed."}, 403); return
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY: self.send_json({"error": "Request exceeds the 8 MB limit."}, 413); return
            body = json.loads(self.rfile.read(length))
            if self.path == "/api/scan/text":
                text = str(body.get("text", ""))
                if len(text) > 1_000_000: self.send_json({"error": "Text exceeds the 1 MB limit."}, 413); return
                result = scan_text(text); remember("Text scan", result["score"], len(result["findings"]), result["level"]); self.send_json(result)
            elif self.path == "/api/scan/document": self.document_scan(body)
            elif self.path == "/api/scan/image": self.image_scan(body)
            elif self.path == "/api/check-url":
                result = check_url(str(body.get("url", ""))); remember("Website check", result["score"], len(result["flags"]), result["level"]); self.send_json(result)
            elif self.path == "/api/assistant":
                findings = body.get("findings", [])
                if not isinstance(findings, list):
                    findings = []
                self.send_json({"answer": assistant_reply(body.get("question", ""), findings), "mode": "local"})
            else: self.send_json({"error": "Not found"}, 404)
        except ValueError as exc: self.send_json({"error": str(exc)}, 400)
        except Exception: self.send_json({"error": "The scan could not be completed."}, 500)
    def image_scan(self, body):
        tesseract = find_tesseract()
        if not tesseract:
            self.send_json({"error": "Image OCR needs Tesseract. In PowerShell run: winget install -e --id UB-Mannheim.TesseractOCR. Then restart PrivacyGuard and try again. Text scanning still works without it."}, 503); return
        data_url = str(body.get("data", ""))
        if not data_url.startswith("data:image/") or ";base64," not in data_url: self.send_json({"error": "Choose a valid image."}, 400); return
        try: data = base64.b64decode(data_url.split(",", 1)[1], validate=True)
        except Exception: self.send_json({"error": "Invalid image encoding."}, 400); return
        if len(data) > 8 * 1024 * 1024: self.send_json({"error": "Image exceeds the 8 MB limit."}, 413); return
        try:
            from PIL import Image
            image = Image.open(io.BytesIO(data)); image.verify(); image = Image.open(io.BytesIO(data)).convert("RGB")
            if image.width * image.height > 20_000_000: raise ValueError("Image dimensions exceed the 20 megapixel limit.")
        except ImportError: self.send_json({"error": "Install Pillow to scan images: pip install Pillow"}, 503); return
        except Exception as exc: self.send_json({"error": str(exc) or "Unsupported or invalid image."}, 400); return
        with tempfile.TemporaryDirectory(prefix="privacyguard-") as tmp:
            input_path = Path(tmp) / "upload.png"; output_path = Path(tmp) / "safe.png"; image.save(input_path, format="PNG")
            proc = subprocess.run([tesseract, str(input_path), "stdout", "tsv"], capture_output=True, text=True, timeout=20)
            if proc.returncode: self.send_json({"error": "OCR could not read this image."}, 422); return
            lines = parse_ocr_tsv(proc.stdout)
            extracted = "\n".join(" ".join(w[0] for w in words) for words in lines.values())
            result = scan_text(extracted); result["text"] = extracted; result["imageSize"] = {"width": image.width, "height": image.height}
            # Conservative redaction: cover every OCR text row containing a matched value.
            boxes = []
            for words in lines.values():
                line = " ".join(w[0] for w in words)
                if any(f["masked"] and re.sub(r"[•]", "", f["masked"]) in line for f in result["findings"]):
                    boxes.append((min(w[1] for w in words), min(w[2] for w in words), max(w[1]+w[3] for w in words), max(w[2]+w[4] for w in words)))
            # Also match by normalized last four digits where OCR spaces punctuation differently.
            from PIL import ImageDraw
            draw = ImageDraw.Draw(image)
            for x1,y1,x2,y2 in boxes: draw.rectangle((max(0,x1-3),max(0,y1-3),min(image.width,x2+3),min(image.height,y2+3)), fill=(8,15,31))
            if result["findings"] and not boxes:
                # OCR found a risk but could not map it to a location: fail closed.
                draw.rectangle((0, 0, image.width, image.height), fill=(8,15,31))
            image.save(output_path, format="PNG"); result["redactedImage"] = "data:image/png;base64," + base64.b64encode(output_path.read_bytes()).decode()
            remember("Screenshot scan", result["score"], len(result["findings"]), result["level"]); self.send_json(result)

    def document_scan(self, body):
        name = str(body.get("name", ""))
        try: raw = base64.b64decode(str(body.get("data", "")), validate=True)
        except Exception: self.send_json({"error": "Invalid file encoding."}, 400); return
        try:
            content = extract_document(name, raw)
        except ImportError: self.send_json({"error": "PDF scanning requires pypdf. DOCX extraction is built in."}, 503); return
        except Exception as exc: self.send_json({"error": str(exc) or "Could not read this document."}, 400); return
        result = scan_text(content); result["source"] = Path(name).name; result["text"] = content
        remember("Document scan", result["score"], len(result["findings"]), result["level"]); self.send_json(result)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    ocr = find_tesseract()
    print(f"PrivacyGuard ready at http://127.0.0.1:{port}")
    print(f"Build: {APP_BUILD}")
    print(f"OCR engine: {ocr or 'not found — restart this server after installing Tesseract'}")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
