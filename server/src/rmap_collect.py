import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from uuid import uuid4


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def download_url(base_url, link, prefix):
    """Use the selected server even when a link names its internal hostname."""
    if not isinstance(link, str) or not link.strip():
        raise ValueError("Empty download link")
    link = link.strip()
    if re.fullmatch(r"[0-9a-fA-F]{32}", link):
        link = prefix.rstrip("/") + "/" + link
    parsed = urlsplit(link)
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        raise ValueError("Unsupported download URL scheme")
    if parsed.netloc:
        link = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    return urljoin(base_url.rstrip("/") + "/", link)


def read_response(request, timeout, limit, receipt, phase):
    try:
        with urlopen(request, timeout=timeout) as response:
            event = {
                "phase": phase,
                "http_status": response.status,
                "content_type": response.headers.get("Content-Type", ""),
            }
            receipt["responses"].append(event)
            content = response.read(limit + 1)
            if len(content) > limit:
                raise ValueError("Response exceeds size limit")
            event["bytes"] = len(content)
            event["sha256"] = hashlib.sha256(content).hexdigest()
            print(f"{phase}: HTTP {response.status}")
            return content
    except HTTPError as error:
        receipt["responses"].append({"phase": phase, "http_status": error.code})
        error.close()
        raise


def post_json(base_url, endpoint, payload, timeout, receipt, phase):
    request = Request(
        urljoin(base_url.rstrip("/") + "/", endpoint),
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    body = read_response(request, timeout, 1024 * 1024, receipt, phase)
    result = json.loads(body)
    if not isinstance(result, dict):
        raise ValueError("Expected a JSON object")
    return result


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="Target server URL, including port")
    parser.add_argument("--target-group", required=True, help="Source group label, e.g. Group_01")
    parser.add_argument("--identity", default="Group_27", help="Your RMAP identity")
    parser.add_argument("--client-private-key", type=Path, required=True)
    parser.add_argument("--server-public-key", type=Path, required=True, help="Target server's public key")
    parser.add_argument("--output-dir", type=Path, default=Path("collected_watermarked_pdfs"))
    parser.add_argument("--initiate-path", default="/api/rmap-initiate")
    parser.add_argument("--get-link-path", default="/api/rmap-get-link")
    parser.add_argument("--download-prefix", default="/api/get-version/", help="Path prefix for a bare 32-hex link")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--max-pdf-bytes", type=int, default=20 * 1024 * 1024)
    args = parser.parse_args()
    base = urlsplit(args.base_url)
    if base.scheme not in ("http", "https") or not base.hostname:
        parser.error("--base-url must be an HTTP(S) server URL")
    if base.username or base.password or base.query or base.fragment:
        parser.error("--base-url must not contain credentials, a query, or a fragment")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", args.target_group):
        parser.error("--target-group must contain only letters, digits, underscores, or hyphens")
    if args.timeout <= 0 or args.max_pdf_bytes <= 0:
        parser.error("Timeout and size limit must be positive")
    return args


def main():
    args = parse_args()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = f"{args.target_group}_rmap_{stamp}_{uuid4().hex[:8]}"
    pdf_path = output_dir / f"{stem}.pdf"
    receipt_path = output_dir / f"{stem}.json"
    receipt = {
        "started_at_utc": utc_now(),
        "target_group": args.target_group,
        "base_url": args.base_url,
        "client_identity": args.identity,
        "endpoints": {
            "initiate": args.initiate_path,
            "get_link": args.get_link_path,
            "bare_link_download_prefix": args.download_prefix,
        },
        "status": "failed",
        "responses": [],
    }
    phase = "preflight"
    exit_code = 1
    try:
        # Import after argument parsing so --help works without these dependencies.
        import pymupdf
        from pgpy import PGPKey
        from rmap import RMAPClient

        if not args.client_private_key.is_file() or not args.server_public_key.is_file():
            raise FileNotFoundError("A configured key file is missing")
        private_key, _ = PGPKey.from_file(str(args.client_private_key))
        public_key, _ = PGPKey.from_file(str(args.server_public_key))
        if private_key.is_public or not public_key.is_public:
            raise ValueError("Expected a client private key and server public key")
        receipt["client_key_fingerprint"] = str(private_key.fingerprint)
        receipt["server_key_fingerprint"] = str(public_key.fingerprint)
        passphrase = getpass("Client private-key passphrase: ") if private_key.is_protected else None
        client = RMAPClient(
            identity=args.identity,
            client_private_key_path=str(args.client_private_key),
            server_public_key_path=str(args.server_public_key),
            passphrase=passphrase,
        )
        del passphrase

        phase = "msg1"
        resp1 = post_json(args.base_url, args.initiate_path, client.build_msg1(), args.timeout, receipt, phase)
        client.process_resp1(resp1)
        print("PASS: RMAP phase 1 completed")

        phase = "msg2"
        resp2 = post_json(args.base_url, args.get_link_path, client.build_msg2(), args.timeout, receipt, phase)
        link = client.process_resp2(resp2)
        url = download_url(args.base_url, link, args.download_prefix)
        print("PASS: RMAP phase 2 completed; download link decrypted")

        phase = "download"
        content = read_response(Request(url, method="GET"), args.timeout, args.max_pdf_bytes, receipt, phase)
        phase = "pdf_validation"
        with pymupdf.open(stream=content, filetype="pdf") as pdf:
            if not pdf.is_pdf or pdf.needs_pass or pdf.page_count < 1:
                raise ValueError("Downloaded PDF is unreadable or empty")
            pages = pdf.page_count
            # Force page parsing; this checks readability, not watermark authenticity.
            for page in pdf:
                page.get_text()

        phase = "save_pdf"
        with pdf_path.open("xb") as output:
            output.write(content)
        receipt.update({
            "status": "success",
            "pdf_file": pdf_path.name,
            "pdf_bytes": len(content),
            "pdf_sha256": hashlib.sha256(content).hexdigest(),
            "pdf_pages": pages,
            "watermark_independently_verified": False,
        })
        print(f"PASS: readable PDF saved ({len(content)} bytes, {pages} pages)")
        print(f"PDF: {pdf_path}")
        print(f"SHA256: {receipt['pdf_sha256']}")
        exit_code = 0
    except Exception as error:
        receipt["failure_phase"] = phase
        receipt["error_type"] = type(error).__name__
        if isinstance(error, ModuleNotFoundError):
            receipt["missing_module"] = error.name
            print(f"Missing Python module: {error.name}", file=sys.stderr)
        if isinstance(error, HTTPError):
            receipt["failure_http_status"] = error.code
        # Avoid logging exception bodies, key material, passphrases, or secret links.
        print(f"FAIL: phase={phase}, error={type(error).__name__}", file=sys.stderr)
        if isinstance(error, HTTPError):
            print(f"HTTP: {error.code}", file=sys.stderr)
    finally:
        receipt["finished_at_utc"] = utc_now()
        with receipt_path.open("x", encoding="utf-8") as output:
            json.dump(receipt, output, ensure_ascii=False, indent=2)
            output.write("\n")
        print(f"Receipt: {receipt_path}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())