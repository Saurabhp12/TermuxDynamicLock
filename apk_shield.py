#!/usr/bin/env python3
"""
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘         CYBERMORANDA APK SHIELD - Android Static Analysis Tool            â•‘
â•‘                     Version 1.0 (Professional Edition)                    â•‘
â•‘                                                                           â•‘
â•‘  Purpose: Defensive, evidence-based Android APK security auditing        â•‘
â•‘  Context: Bug bounties, privacy reviews, security research               â•‘
â•‘  Not for: Exploitation, malware creation, or offensive purposes           â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
"""

import os
import sys
import json
import re
import hashlib
import zipfile
import struct
import math
import argparse
import webbrowser
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime
from xml.etree import ElementTree as ET
from collections import Counter, defaultdict
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading
import tempfile

# ============================================================================
# 1. UTILITY & HASHING
# ============================================================================

class FileAnalyzer:
    """Hash, entropy, and basic file forensics."""

    @staticmethod
    def calculate_hashes(filepath):
        """Calculate MD5 and SHA256 of file."""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()

        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)

        return {
            'md5': md5_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest(),
            'size_bytes': os.path.getsize(filepath),
            'size_mb': round(os.path.getsize(filepath) / (1024*1024), 2)
        }

    @staticmethod
    def shannon_entropy(data):
        """Calculate Shannon entropy (0-8 for bytes)."""
        if not data:
            return 0.0

        entropy = 0.0
        for byte_count in Counter(data).values():
            probability = byte_count / len(data)
            entropy -= probability * math.log2(probability)

        return round(entropy, 2)

    @staticmethod
    def is_obfuscated(entropy_score):
        """Heuristic: entropy > 7.5 suggests compression/obfuscation."""
        return entropy_score > 7.5


# ============================================================================
# 2. APK EXTRACTION & PARSING
# ============================================================================

class APKExtractor:
    """Extract and parse APK contents safely."""

    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.temp_dir = tempfile.mkdtemp()
        self.manifest_xml = None
        self.resources_strings = {}
        self.dex_data = None
        self.strings_xml_findings = []

    def extract(self):
        """Extract APK (ZIP format)."""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                zf.extractall(self.temp_dir)
            return True
        except Exception as e:
            print(f"[!] APK extraction failed: {e}")
            return False

    def parse_manifest(self):
        """Parse AndroidManifest.xml (binary format -> text)."""
        manifest_path = os.path.join(self.temp_dir, 'AndroidManifest.xml')

        if not os.path.exists(manifest_path):
            return None

        try:
            # Android binary XML uses custom format; we'll use a simple parser
            # For production, consider android-binary-xml library
            with open(manifest_path, 'rb') as f:
                self.manifest_xml = f.read()

            # Extract text strings from binary XML
            return self._extract_strings_from_binary_xml(self.manifest_xml)
        except Exception as e:
            print(f"[!] Manifest parsing error: {e}")
            return None

    def _extract_strings_from_binary_xml(self, binary_data):
        """Extract readable strings from binary XML for analysis."""
        # Look for common UTF-16 and ASCII patterns
        strings = []

        # ASCII strings (4+ chars)
        ascii_strings = re.findall(b'[ -~]{4,}', binary_data)
        for s in ascii_strings:
            try:
                strings.append(s.decode('ascii', errors='ignore'))
            except:
                pass

        # UTF-16 strings
        try:
            utf16_decoded = binary_data.decode('utf-16-le', errors='ignore')
            utf16_strings = re.findall(r'[\w\.\-:/]+', utf16_decoded)
            strings.extend(utf16_strings)
        except:
            pass

        return list(set(strings))  # Deduplicate

    def extract_dex(self):
        """Extract DEX file for analysis."""
        dex_path = os.path.join(self.temp_dir, 'classes.dex')

        if os.path.exists(dex_path):
            with open(dex_path, 'rb') as f:
                self.dex_data = f.read()
            return self.dex_data

        return None

    def cleanup(self):
        """Remove temp directory."""
        import shutil
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass


# ============================================================================
# 3. MANIFEST SECURITY ANALYSIS
# ============================================================================

class ManifestAnalyzer:
    """Analyze AndroidManifest.xml for security issues."""

    # Dangerous permissions per Android docs
    DANGEROUS_PERMISSIONS = {
        'READ_CONTACTS': 'MEDIUM',
        'WRITE_CONTACTS': 'MEDIUM',
        'READ_CALL_LOG': 'HIGH',
        'WRITE_CALL_LOG': 'HIGH',
        'GET_ACCOUNTS': 'MEDIUM',
        'READ_PHONE_STATE': 'MEDIUM',
        'READ_PHONE_NUMBERS': 'MEDIUM',
        'CALL_PHONE': 'HIGH',
        'ANSWER_PHONE_CALLS': 'HIGH',
        'READ_SMS': 'HIGH',
        'SEND_SMS': 'HIGH',
        'RECEIVE_SMS': 'HIGH',
        'READ_CALENDAR': 'MEDIUM',
        'WRITE_CALENDAR': 'MEDIUM',
        'CAMERA': 'HIGH',
        'RECORD_AUDIO': 'HIGH',
        'ACCESS_FINE_LOCATION': 'HIGH',
        'ACCESS_COARSE_LOCATION': 'MEDIUM',
        'ACCESS_BACKGROUND_LOCATION': 'HIGH',
        'BODY_SENSORS': 'MEDIUM',
        'BODY_SENSORS_BACKGROUND': 'HIGH',
        'READ_EXTERNAL_STORAGE': 'MEDIUM',
        'WRITE_EXTERNAL_STORAGE': 'MEDIUM',
        'ACCESS_MEDIA_LOCATION': 'MEDIUM',
    }

    def __init__(self, manifest_strings):
        self.manifest_strings = manifest_strings or []
        self.findings = []
        self.metadata = {}

    def analyze(self):
        """Run all manifest checks."""
        self._check_debuggable()
        self._check_backup()
        self._check_cleartext()
        self._check_exported_components()
        self._check_permissions()
        self._extract_metadata()

        return self.findings

    def _check_debuggable(self):
        """Check for debuggable flag."""
        for s in self.manifest_strings:
            if 'debuggable' in s.lower() and ('true' in s.lower()):
                self.findings.append({
                    'type': 'DEBUGGABLE',
                    'severity': 'HIGH',
                    'title': 'Debuggable APK',
                    'description': 'App compiled with debuggable=true. Allows attacker debugging via adb.',
                    'evidence': f'String found: {s}',
                    'remediation': 'Set android:debuggable="false" in AndroidManifest.xml',
                    'false_positive_note': 'Normal during development, must be disabled for production.'
                })

    def _check_backup(self):
        """Check for allowBackup flag."""
        for s in self.manifest_strings:
            if 'allowbackup' in s.lower() and ('true' in s.lower()):
                self.findings.append({
                    'type': 'BACKUP_ENABLED',
                    'severity': 'MEDIUM',
                    'title': 'Backup Enabled',
                    'description': 'allowBackup=true exposes app data via `adb backup`.',
                    'evidence': f'String found: {s}',
                    'remediation': 'Set android:allowBackup="false" unless backup is essential.',
                    'false_positive_note': 'Some apps may legitimately require backups.'
                })

    def _check_cleartext(self):
        """Check for cleartext traffic."""
        for s in self.manifest_strings:
            if 'cleartexttraffic' in s.lower() and ('true' in s.lower()):
                self.findings.append({
                    'type': 'CLEARTEXT_TRAFFIC',
                    'severity': 'HIGH',
                    'title': 'Cleartext Traffic Allowed',
                    'description': 'HTTP traffic (unencrypted) is explicitly allowed.',
                    'evidence': f'String found: {s}',
                    'remediation': 'Use HTTPS exclusively; set usesCleartextTraffic=false.',
                    'false_positive_note': 'Rare legitimate cases (legacy APIs, local testing).'
                })

    def _check_exported_components(self):
        """Check for exported components without protections."""
        exported_keywords = ['exported', 'action', 'category']

        for s in self.manifest_strings:
            if 'exported' in s.lower() and 'true' in s.lower():
                self.findings.append({
                    'type': 'EXPORTED_COMPONENT',
                    'severity': 'MEDIUM',
                    'title': 'Exported Component Detected',
                    'description': 'Activity/Service/Provider exported without intent filters may be abused.',
                    'evidence': f'String found: {s}',
                    'remediation': 'Restrict exported components or add intent filters + permissions.',
                    'false_positive_note': 'Launchers and widgets may intentionally be exported.'
                })

    def _check_permissions(self):
        """Extract and analyze permissions."""
        for s in self.manifest_strings:
            for perm, severity in self.DANGEROUS_PERMISSIONS.items():
                if perm.lower() in s.lower():
                    self.findings.append({
                        'type': 'DANGEROUS_PERMISSION',
                        'severity': severity,
                        'title': f'Dangerous Permission: {perm}',
                        'description': self._describe_permission(perm),
                        'evidence': f'Permission declaration found: {s}',
                        'remediation': f'Verify {perm} is necessary. Runtime permission handling required.',
                        'false_positive_note': self._context_aware_note(perm)
                    })

    def _describe_permission(self, perm):
        """Provide context-aware permission descriptions."""
        descriptions = {
            'CAMERA': 'App can access device camera. Verify usage.',
            'RECORD_AUDIO': 'App can record audio without visual indicator (on older Android).',
            'READ_CONTACTS': 'App can read all contacts.',
            'READ_CALL_LOG': 'App can read call history.',
            'READ_SMS': 'App can access all SMS messages.',
            'SEND_SMS': 'App can send SMS charges to user.',
            'ACCESS_FINE_LOCATION': 'Precise GPS location access.',
            'READ_EXTERNAL_STORAGE': 'Can access all files on device storage.',
        }
        return descriptions.get(perm, f'Permission {perm} grants sensitive access.')

    def _context_aware_note(self, perm):
        """Context-aware false positive notes."""
        notes = {
            'CAMERA': 'Camera apps, video conferencing, social media may legitimately need this.',
            'READ_CONTACTS': 'Messaging apps, CRM tools, phone need this.',
            'RECORD_AUDIO': 'Voice calling, meeting apps legitimately need this.',
            'ACCESS_FINE_LOCATION': 'Maps, ride-sharing, weather apps need this.',
        }
        return notes.get(perm, f'Check if {perm} is justified by app functionality.')

    def _extract_metadata(self):
        """Extract app metadata from strings."""
        for s in self.manifest_strings:
            if 'package=' in s.lower():
                self.metadata['package'] = s
            if 'versioncode=' in s.lower():
                self.metadata['version_code'] = s
            if 'versionname=' in s.lower():
                self.metadata['version_name'] = s


# ============================================================================
# 4. SECRET & CREDENTIAL SCANNER
# ============================================================================

class SecretScanner:
    """Scan for hardcoded secrets, API keys, credentials."""

    PATTERNS = {
        'google_api_key': {
            'pattern': r'AIza[0-9A-Za-z\-_]{35}',
            'severity': 'HIGH',
            'description': 'Google API Key (can be used for unauthorized API calls)'
        },
        'aws_key': {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'severity': 'CRITICAL',
            'description': 'AWS Access Key ID'
        },
        'firebase_url': {
            'pattern': r'https://[a-z0-9-]+\.firebaseio\.com',
            'severity': 'MEDIUM',
            'description': 'Firebase Database URL (may be accessible if rules misconfigured)'
        },
        'private_key': {
            'pattern': r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY',
            'severity': 'CRITICAL',
            'description': 'Private cryptographic key embedded'
        },
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.?[A-Za-z0-9_./-]*',
            'severity': 'HIGH',
            'description': 'JWT token (can grant unauthorized access)'
        },
        'generic_token': {
            'pattern': r'(token|apikey|api_key|secret)\s*[=:]\s*["']?[A-Za-z0-9_\-]{20,}',
            'severity': 'HIGH',
            'description': 'Possible hardcoded token/key'
        },
        'sql_connection': {
            'pattern': r'(password|passwd|pwd)\s*[=:]\s*["'][^"']+["']',
            'severity': 'CRITICAL',
            'description': 'Hardcoded database password'
        },
    }

    def __init__(self, data_sources):
        self.data_sources = data_sources  # List of strings/data to scan
        self.findings = []

    def scan(self):
        """Scan for secrets."""
        for source in self.data_sources:
            if not isinstance(source, str):
                try:
                    source = source.decode('utf-8', errors='ignore')
                except:
                    source = str(source)

            for key, rule in self.PATTERNS.items():
                matches = re.finditer(rule['pattern'], source, re.IGNORECASE)
                for match in matches:
                    self.findings.append({
                        'type': 'SECRET_DETECTED',
                        'severity': rule['severity'],
                        'title': f'Potential Secret: {key.upper()}',
                        'description': rule['description'],
                        'evidence': f'Pattern: {match.group(0)[:50]}...' if len(match.group(0)) > 50 else match.group(0),
                        'remediation': 'Remove secret from code. Rotate keys. Use environment variables or secure config.',
                        'false_positive_note': 'Verify if match is actual secret or false positive (e.g., test data, public URLs).'
                    })

        return self.findings


# ============================================================================
# 5. NETWORK & ENDPOINT ANALYSIS
# ============================================================================

class NetworkAnalyzer:
    """Extract and classify network endpoints."""

    # Common benign libraries (whitelist to reduce noise)
    BENIGN_DOMAINS = {
        'google.com', 'googleapis.com', 'gstatic.com',
        'android.com', 'android.googleapis.com',
        'firebase.google.com', 'firebaseio.com',
        'github.com', 'githubusercontent.com',
        'cloudflare.com', 'akamai.com',
        'amazonaws.com',
        'fastly.net',
        'jsDelivr.net',
        'cdnjs.com',
        'stackoverflow.com',
        'gradle.org',
        'maven.org',
        'apache.org',
        'junit.org',
        'jetbrains.com',
    }

    ENDPOINT_TYPES = {
        'analytics': r'(analytics|amplitude|mixpanel|flurry|branch\.io|segment|firebase\.google\.com)',
        'ads': r'(admob|doubleclick|google\.com\/ads|flurry)',
        'social': r'(facebook\.com|twitter\.com|instagram\.com|linkedin\.com)',
        'messaging': r'(firebase\.googleapis\.com|pusher\.com|twilio)',
        'tracking': r'(google\.com|facebook\.com|doubleclick)',
    }

    def __init__(self, data_sources):
        self.data_sources = data_sources
        self.endpoints = defaultdict(list)
        self.classified = defaultdict(list)

    def analyze(self):
        """Extract and classify endpoints."""
        for source in self.data_sources:
            if not isinstance(source, str):
                try:
                    source = source.decode('utf-8', errors='ignore')
                except:
                    source = str(source)

            # URLs
            urls = re.findall(r'https?://[^\s'"<>]+', source)
            for url in urls:
                parsed = urlparse(url)
                domain = parsed.netloc

                if not self._is_benign(domain):
                    self.endpoints['url'].append({
                        'url': url,
                        'domain': domain,
                        'type': self._classify_endpoint(url)
                    })

            # IPs
            ips = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', source)
            for ip in ips:
                if not self._is_private_ip(ip):
                    self.endpoints['ip'].append(ip)

        return dict(self.endpoints)

    def _is_benign(self, domain):
        """Check if domain is in benign whitelist."""
        for benign in self.BENIGN_DOMAINS:
            if benign in domain.lower():
                return True
        return False

    def _is_private_ip(self, ip):
        """Check if IP is private/local."""
        parts = [int(x) for x in ip.split('.')]
        if parts[0] == 127 or parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        return False

    def _classify_endpoint(self, url):
        """Classify endpoint type."""
        for endpoint_type, pattern in self.ENDPOINT_TYPES.items():
            if re.search(pattern, url, re.IGNORECASE):
                return endpoint_type
        return 'other'


# ============================================================================
# 6. BEHAVIOR INFERENCE
# ============================================================================

class BehaviorInference:
    """Infer possible app behaviors from permission/feature combinations."""

    BEHAVIOR_PATTERNS = [
        {
            'name': 'Potential Spyware',
            'indicators': ['READ_CONTACTS', 'READ_SMS', 'ACCESS_FINE_LOCATION', 'RECORD_AUDIO'],
            'confidence': 'medium',
            'description': 'Combination suggests unauthorized surveillance capability.'
        },
        {
            'name': 'Potential Banking Trojan',
            'indicators': ['SYSTEM_ALERT_WINDOW', 'READ_SMS', 'SEND_SMS', 'CALL_PHONE'],
            'confidence': 'high',
            'description': 'Overlay + SMS + calling suggests banking credential theft.'
        },
        {
            'name': 'Potential Adware',
            'indicators': ['ACCESS_NETWORK_STATE', 'INTERNET', 'RECEIVE_BOOT_COMPLETED', 'VIBRATE'],
            'confidence': 'low',
            'description': 'Many permissions common to ad-supported apps; context-dependent.'
        },
        {
            'name': 'Potential SMS Hijacker',
            'indicators': ['READ_SMS', 'SEND_SMS', 'INTERCEPT_SMS'],
            'confidence': 'high',
            'description': 'Direct SMS control without user intent.'
        },
    ]

    def __init__(self, permissions):
        self.permissions = [p.upper() for p in (permissions or [])]

    def infer(self):
        """Infer possible behaviors."""
        inferred = []

        for pattern in self.BEHAVIOR_PATTERNS:
            matching_indicators = [
                ind for ind in pattern['indicators']
                if any(ind in p for p in self.permissions)
            ]

            if len(matching_indicators) >= len(pattern['indicators']) - 1:
                inferred.append({
                    'behavior': pattern['name'],
                    'confidence': pattern['confidence'],
                    'description': pattern['description'],
                    'matched_permissions': matching_indicators,
                    'caveat': 'This is a static heuristic. Actual behavior requires dynamic analysis or code review.'
                })

        return inferred


# ============================================================================
# 7. RISK SCORING ENGINE
# ============================================================================

class RiskScorer:
    """Calculate overall risk score and verdict."""

    def __init__(self, findings, inferred_behaviors, entropy_score):
        self.findings = findings
        self.inferred_behaviors = inferred_behaviors
        self.entropy_score = entropy_score
        self.vt_result = None

    def set_vt_result(self, result):
        """Set VirusTotal result to cap score if clean."""
        self.vt_result = result

    def calculate_score(self):
        """Calculate risk score (0-100)."""
        score = 0
        breakdown = {}

        # High severity findings (25 points max)
        high_findings = [f for f in self.findings if f.get('severity') == 'HIGH']
        critical_findings = [f for f in self.findings if f.get('severity') == 'CRITICAL']

        high_score = min(len(high_findings) * 5, 15)
        critical_score = min(len(critical_findings) * 10, 25)

        score += high_score + critical_score
        breakdown['severity_findings'] = high_score + critical_score

        # Medium findings (10 points)
        medium_findings = [f for f in self.findings if f.get('severity') == 'MEDIUM']
        medium_score = min(len(medium_findings) * 2, 10)
        score += medium_score
        breakdown['medium_findings'] = medium_score

        # Entropy heuristic (5 points)
        if self.entropy_score > 7.5:
            score += 5
            breakdown['obfuscation'] = 5
        else:
            breakdown['obfuscation'] = 0

        # Inferred behaviors (15 points)
        behavior_score = len(self.inferred_behaviors) * 5
        behavior_score = min(behavior_score, 15)
        score += behavior_score
        breakdown['inferred_behaviors'] = behavior_score

        # VirusTotal cap (if clean, cap to 25)
        if self.vt_result and self.vt_result.get('clean'):
            score = min(score, 25)
            breakdown['vt_cap'] = 'Applied (VirusTotal clean)'

        score = min(score, 100)

        return {
            'score': score,
            'breakdown': breakdown,
            'verdict': self._verdict(score)
        }

    def _verdict(self, score):
        """Determine verdict category."""
        if score <= 20:
            return 'SAFE'
        elif score <= 50:
            return 'MEDIUM'
        elif score <= 75:
            return 'SUSPICIOUS'
        else:
            return 'CRITICAL'


# ============================================================================
# 8. HTML REPORT GENERATION
# ============================================================================

class ReportGenerator:
    """Generate professional HTML report."""

    def __init__(self, analysis_results):
        self.results = analysis_results
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def generate_html(self):
        """Generate complete HTML report."""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberMoranda APK Shield - Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f0f0f;
            color: #e0e0e0;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}

        header {{
            border-bottom: 2px solid #1e90ff;
            margin-bottom: 40px;
            padding-bottom: 20px;
        }}

        h1 {{
            color: #1e90ff;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}

        .subtitle {{
            color: #888;
            font-size: 0.9em;
        }}

        .banner {{
            background: #1a1a1a;
            border-left: 4px solid #1e90ff;
            padding: 15px;
            margin-bottom: 30px;
            border-radius: 4px;
        }}

        .banner-title {{
            font-weight: bold;
            color: #1e90ff;
            margin-bottom: 5px;
        }}

        .score-card {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 40px;
        }}

        .score-box {{
            background: #1a1a1a;
            border: 2px solid #333;
            border-radius: 8px;
            padding: 25px;
            text-align: center;
        }}

        .score-value {{
            font-size: 3.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }}

        .score-safe {{ color: #00ff00; }}
        .score-medium {{ color: #ffaa00; }}
        .score-suspicious {{ color: #ff6600; }}
        .score-critical {{ color: #ff0000; }}

        .score-label {{
            font-size: 1.2em;
            color: #aaa;
            margin-bottom: 15px;
        }}

        .verdict {{
            font-weight: bold;
            font-size: 1.3em;
            padding: 10px;
            border-radius: 4px;
            display: inline-block;
        }}

        .verdict-safe {{ background: rgba(0,255,0,0.1); color: #00ff00; border: 1px solid #00ff00; }}
        .verdict-medium {{ background: rgba(255,170,0,0.1); color: #ffaa00; border: 1px solid #ffaa00; }}
        .verdict-suspicious {{ background: rgba(255,102,0,0.1); color: #ff6600; border: 1px solid #ff6600; }}
        .verdict-critical {{ background: rgba(255,0,0,0.1); color: #ff0000; border: 1px solid #ff0000; }}

        .metadata {{
            background: #1a1a1a;
            border: 1px solid #333;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }}

        .metadata-row {{
            display: grid;
            grid-template-columns: 200px 1fr;
            margin-bottom: 12px;
            padding-bottom: 12px;
            border-bottom: 1px solid #333;
        }}

        .metadata-row:last-child {{
            border-bottom: none;
        }}

        .metadata-label {{
            color: #1e90ff;
            font-weight: bold;
        }}

        .metadata-value {{
            color: #e0e0e0;
            word-break: break-all;
        }}

        h2 {{
            color: #1e90ff;
            margin-top: 40px;
            margin-bottom: 20px;
            border-bottom: 2px solid #333;
            padding-bottom: 10px;
        }}

        .finding {{
            background: #1a1a1a;
            border-left: 4px solid #333;
            border-radius: 4px;
            padding: 20px;
            margin-bottom: 20px;
        }}

        .finding-critical {{ border-left-color: #ff0000; }}
        .finding-high {{ border-left-color: #ff6600; }}
        .finding-medium {{ border-left-color: #ffaa00; }}
        .finding-low {{ border-left-color: #00ff00; }}

        .finding-title {{
            font-weight: bold;
            font-size: 1.1em;
            margin-bottom: 10px;
            color: #e0e0e0;
        }}

        .finding-severity {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin-bottom: 10px;
        }}

        .severity-critical {{ background: rgba(255,0,0,0.2); color: #ff0000; }}
        .severity-high {{ background: rgba(255,102,0,0.2); color: #ff6600; }}
        .severity-medium {{ background: rgba(255,170,0,0.2); color: #ffaa00; }}
        .severity-low {{ background: rgba(0,255,0,0.2); color: #00ff00; }}

        .finding-section {{
            margin-bottom: 15px;
        }}

        .section-label {{
            color: #888;
            font-size: 0.9em;
            font-weight: bold;
            text-transform: uppercase;
            margin-bottom: 5px;
        }}

        .section-content {{
            color: #ddd;
            padding-left: 10px;
            border-left: 2px solid #333;
        }}

        .endpoint-list {{
            background: #0a0a0a;
            border: 1px solid #333;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 15px;
        }}

        .endpoint-item {{
            padding: 8px;
            margin-bottom: 5px;
            background: #1a1a1a;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }}

        .disclaimer {{
            background: rgba(255,170,0,0.05);
            border: 1px solid rgba(255,170,0,0.3);
            border-radius: 4px;
            padding: 15px;
            margin-top: 40px;
            color: #ddd;
            font-size: 0.9em;
        }}

        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #333;
            color: #666;
            font-size: 0.85em;
        }}

        .section-summary {{
            background: #0a0a0a;
            border: 1px solid #333;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 20px;
        }}

        .section-summary-stat {{
            display: inline-block;
            margin-right: 25px;
            margin-bottom: 10px;
        }}

        .summary-number {{
            color: #1e90ff;
            font-weight: bold;
            font-size: 1.3em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>âš”ï¸ CyberMoranda APK Shield</h1>
            <p class="subtitle">Professional Android Static Analysis Report | {self.timestamp}</p>
        </header>

        <div class="banner">
            <div class="banner-title">ðŸ“‹ Analysis Report</div>
            <p>This report documents static analysis findings of the provided APK file.</p>
        </div>

        {self._render_score_section()}
        {self._render_metadata_section()}
        {self._render_findings_section()}
        {self._render_endpoints_section()}
        {self._render_behavior_section()}
        {self._render_false_positives_section()}
        {self._render_disclaimer()}

        <div class="footer">
            <strong>CyberMoranda APK Shield v1.0</strong> | Defensive Security Analysis | 
            <em>For security research, bug bounties, and privacy audits</em>
        </div>
    </div>
</body>
</html>"""

        return html

    def _render_score_section(self):
        """Render risk score section."""
        score_data = self.results.get('score', {})
        score = score_data.get('score', 0)
        verdict = score_data.get('verdict', 'UNKNOWN')

        score_class = f'score-{verdict.lower()}'
        verdict_class = f'verdict-{verdict.lower()}'

        breakdown_html = ""
        for key, value in score_data.get('breakdown', {}).items():
            if isinstance(value, str):
                breakdown_html += f"<div class='section-summary-stat'><span class='summary-number'>{value}</span> {key.replace('_', ' ').title()}</div>"
            else:
                breakdown_html += f"<div class='section-summary-stat'><span class='summary-number'>{value}</span> {key.replace('_', ' ').title()}</div>"

        return f"""
        <div class="score-card">
            <div class="score-box">
                <div class="score-label">Risk Score</div>
                <div class="score-value {score_class}">{score}</div>
                <div class="verdict {verdict_class}">{verdict}</div>
            </div>
            <div class="score-box">
                <div class="score-label">Score Breakdown</div>
                <div class="section-summary">
                    {breakdown_html}
                </div>
            </div>
        </div>
        """

    def _render_metadata_section(self):
        """Render file metadata."""
        metadata = self.results.get('metadata', {})

        rows = ""
        for key, value in metadata.items():
            rows += f"""
            <div class="metadata-row">
                <div class="metadata-label">{key.replace('_', ' ').title()}</div>
                <div class="metadata-value">{value}</div>
            </div>
            """

        return f"""
        <h2>ðŸ“¦ File Metadata</h2>
        <div class="metadata">
            {rows}
        </div>
        """

    def _render_findings_section(self):
        """Render security findings."""
        findings = self.results.get('findings', [])

        if not findings:
            return """
            <h2>ðŸ” Security Findings</h2>
            <div class="banner">
                <p>No security findings detected. âœ“</p>
            </div>
            """

        findings_html = ""
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN').lower()
            findings_html += f"""
            <div class="finding finding-{severity}">
                <div class="finding-title">{finding.get('title', 'Finding')}</div>
                <div class="finding-severity severity-{severity}">{finding.get('severity', 'UNKNOWN')}</div>

                <div class="finding-section">
                    <div class="section-label">Description</div>
                    <div class="section-content">{finding.get('description', '')}</div>
                </div>

                <div class="finding-section">
                    <div class="section-label">Evidence</div>
                    <div class="section-content">{finding.get('evidence', '')}</div>
                </div>

                <div class="finding-section">
                    <div class="section-label">Remediation</div>
                    <div class="section-content">{finding.get('remediation', '')}</div>
                </div>

                <div class="finding-section">
                    <div class="section-label">False Positive Note</div>
                    <div class="section-content">{finding.get('false_positive_note', '')}</div>
                </div>
            </div>
            """

        return f"""
        <h2>ðŸ” Security Findings ({len(findings)})</h2>
        {findings_html}
        """

    def _render_endpoints_section(self):
        """Render network endpoints."""
        endpoints = self.results.get('endpoints', {})

        html = "<h2>ðŸŒ Network Endpoints</h2>"

        if not endpoints.get('url') and not endpoints.get('ip'):
            html += '<div class="banner"><p>No external network endpoints detected.</p></div>'
            return html

        if endpoints.get('url'):
            html += '<div class="section-summary"><div><strong>URLs Found:</strong></div>'
            for url_data in endpoints['url']:
                html += f"""
                <div class="endpoint-item">
                    {url_data.get('url', '')} 
                    <span style="color: #888;">({url_data.get('type', 'unknown')})</span>
                </div>
                """
            html += '</div>'

        if endpoints.get('ip'):
            html += '<div class="section-summary"><div><strong>IP Addresses:</strong></div>'
            for ip in endpoints['ip']:
                html += f'<div class="endpoint-item">{ip}</div>'
            html += '</div>'

        return html

    def _render_behavior_section(self):
        """Render inferred behaviors."""
        behaviors = self.results.get('inferred_behaviors', [])

        if not behaviors:
            return '<h2>ðŸŽ¯ Behavior Inference</h2><div class="banner"><p>No suspicious behavior patterns inferred.</p></div>'

        html = '<h2>ðŸŽ¯ Behavior Inference</h2>'
        for behavior in behaviors:
            html += f"""
            <div class="finding finding-medium">
                <div class="finding-title">{behavior.get('behavior', 'Behavior')}</div>
                <div class="finding-severity severity-medium">{behavior.get('confidence', 'UNKNOWN').upper()}</div>

                <div class="finding-section">
                    <div class="section-label">Description</div>
                    <div class="section-content">{behavior.get('description', '')}</div>
                </div>

                <div class="finding-section">
                    <div class="section-label">Matched Permissions</div>
                    <div class="section-content">{', '.join(behavior.get('matched_permissions', []))}</div>
                </div>

                <div class="finding-section">
                    <div class="section-label">Caveat</div>
                    <div class="section-content">{behavior.get('caveat', '')}</div>
                </div>
            </div>
            """

        return html

    def _render_false_positives_section(self):
        """Render false positive context."""
        return """
        <h2>âš ï¸ About False Positives</h2>
        <div class="section-summary">
            <p><strong>Important:</strong> Static analysis findings are not definitive proof of malicious intent. Context matters:</p>
            <ul style="margin-top: 10px; margin-left: 20px; color: #ddd;">
                <li><strong>Permissions:</strong> Legitimate apps request sensitive permissions. A messenger app needs contacts; a maps app needs location.</li>
                <li><strong>Exported Components:</strong> Launchers and system apps intentionally export components.</li>
                <li><strong>Network Endpoints:</strong> Analytics, ads, and cloud services are common in legitimate apps.</li>
                <li><strong>Obfuscation:</strong> High entropy may indicate compression or legitimate code hardening, not just malware.</li>
                <li><strong>Behavior Patterns:</strong> Heuristics catch suspicious combinations but produce false positives in legitimate apps.</li>
            </ul>
            <p style="margin-top: 15px;"><strong>Verification Steps:</strong></p>
            <ol style="margin-top: 10px; margin-left: 20px; color: #ddd;">
                <li>Cross-reference findings with published app privacy policies</li>
                <li>Review app reviews on trusted app stores</li>
                <li>Use dynamic analysis or sandboxing for behavioral verification</li>
                <li>Check VirusTotal reputation scores</li>
                <li>Review code or disassembly for high-risk findings</li>
            </ol>
        </div>
        """

    def _render_disclaimer(self):
        """Render legal disclaimer."""
        return """
        <div class="disclaimer">
            <strong>âš–ï¸ Legal Disclaimer</strong>
            <p>This tool is provided for defensive security research, bug bounties, privacy audits, and authorized penetration testing only. 
            Users are responsible for obtaining proper authorization before analyzing any APK file. 
            Findings are based on static analysis heuristics and are not definitive conclusions about app behavior or intent. 
            This tool provides no guarantees regarding accuracy or completeness. 
            CyberMoranda assumes no liability for misuse or damages resulting from tool usage.</p>
        </div>
        """


# ============================================================================
# 9. MAIN ANALYSIS ORCHESTRATOR
# ============================================================================

class APKShield:
    """Main orchestrator for APK analysis."""

    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.results = {
            'metadata': {},
            'findings': [],
            'endpoints': {},
            'inferred_behaviors': [],
            'score': {}
        }

    def analyze(self):
        """Run complete analysis."""

        print("\n" + "="*70)
        print(" CYBERMORANDA APK SHIELD - Analysis Starting")
        print("="*70 + "\n")

        # 1. File hashing & entropy
        print("[*] Analyzing file metadata...")
        file_analyzer = FileAnalyzer()
        hashes = file_analyzer.calculate_hashes(self.apk_path)

        self.results['metadata'].update({
            'file': os.path.basename(self.apk_path),
            'md5': hashes['md5'],
            'sha256': hashes['sha256'],
            'size': f"{hashes['size_mb']} MB",
        })

        # 2. Extract APK
        print("[*] Extracting APK contents...")
        extractor = APKExtractor(self.apk_path)
        if not extractor.extract():
            print("[!] Failed to extract APK. Aborting.")
            return None

        # 3. Parse manifest
        print("[*] Parsing AndroidManifest.xml...")
        manifest_strings = extractor.parse_manifest()

        # 4. Extract DEX
        print("[*] Analyzing DEX bytecode...")
        dex_data = extractor.extract_dex()
        if dex_data:
            entropy = FileAnalyzer.shannon_entropy(dex_data)
            self.results['metadata']['entropy'] = entropy
            self.results['metadata']['obfuscation'] = 'Possible' if FileAnalyzer.is_obfuscated(entropy) else 'None detected'

        # 5. Manifest security analysis
        print("[*] Analyzing manifest security...")
        manifest_analyzer = ManifestAnalyzer(manifest_strings)
        manifest_findings = manifest_analyzer.analyze()
        self.results['findings'].extend(manifest_findings)

        # 6. Secret scanning
        print("[*] Scanning for secrets...")
        secret_scanner = SecretScanner(manifest_strings or [])
        if dex_data:
            secret_scanner.data_sources.append(dex_data)
        secret_findings = secret_scanner.scan()
        self.results['findings'].extend(secret_findings)

        # 7. Network analysis
        print("[*] Analyzing network endpoints...")
        network_analyzer = NetworkAnalyzer(manifest_strings or [])
        if dex_data:
            network_analyzer.data_sources.append(dex_data)
        endpoints = network_analyzer.analyze()
        self.results['endpoints'] = endpoints

        # 8. Behavior inference
        print("[*] Inferring possible behaviors...")
        permissions = []
        for s in (manifest_strings or []):
            if 'uses-permission' in s.lower():
                permissions.append(s)

        behavior_inf = BehaviorInference(permissions)
        inferred = behavior_inf.infer()
        self.results['inferred_behaviors'] = inferred

        # 9. Risk scoring
        print("[*] Calculating risk score...")
        entropy = self.results['metadata'].get('entropy', 0)
        scorer = RiskScorer(self.results['findings'], inferred, entropy)
        score_result = scorer.calculate_score()
        self.results['score'] = score_result

        extractor.cleanup()

        print("\n[âœ“] Analysis complete!")
        print(f"[âœ“] Risk Score: {score_result['score']}/100 ({score_result['verdict']})")
        print(f"[âœ“] Findings: {len(self.results['findings'])}")
        print(f"[âœ“] Inferred Behaviors: {len(inferred)}")

        return self.results

    def generate_report(self, output_path=None):
        """Generate HTML report."""
        if not self.results or not self.results.get('score'):
            print("[!] No analysis results. Run analyze() first.")
            return None

        generator = ReportGenerator(self.results)
        html = generator.generate_html()

        if not output_path:
            output_path = os.path.splitext(self.apk_path)[0] + '_shield_report.html'

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        print(f"\n[âœ“] Report saved: {output_path}")
        return output_path


# ============================================================================
# 10. CLI INTERFACE
# ============================================================================

def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description='CyberMoranda APK Shield - Professional Android Static Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/app.apk
  %(prog)s app.apk --report custom_report.html --server
        """
    )

    parser.add_argument('apk', help='Path to APK file')
    parser.add_argument('--report', help='Output HTML report path (default: apk_name_shield_report.html)')
    parser.add_argument('--server', action='store_true', help='Launch local HTTP server to view report')
    parser.add_argument('--no-browser', action='store_true', help='Don\'t auto-open browser')

    args = parser.parse_args()

    if not os.path.exists(args.apk):
        print(f"[!] APK not found: {args.apk}")
        sys.exit(1)

    # Run analysis
    shield = APKShield(args.apk)
    results = shield.analyze()

    if not results:
        sys.exit(1)

    # Generate report
    report_path = shield.generate_report(args.report)

    # Optional: launch server
    if args.server:
        launch_report_server(report_path, args.no_browser)


def launch_report_server(report_path, no_browser=False):
    """Launch local HTTP server to view report."""
    report_dir = os.path.dirname(os.path.abspath(report_path))
    report_name = os.path.basename(report_path)

    os.chdir(report_dir)

    # Custom handler to serve the report
    class ReportHandler(SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/':
                self.path = '/' + report_name
            return SimpleHTTPRequestHandler.do_GET(self)

        def log_message(self, format, *args):
            pass  # Suppress logs

    server = HTTPServer(('127.0.0.1', 8080), ReportHandler)

    print("\n" + "="*70)
    print(" LOCAL HTTP SERVER LAUNCHED")
    print("="*70)
    print(f"[âœ“] Report available at: http://127.0.0.1:8080/{report_name}")
    print("[*] Press Ctrl+C to stop server")
    print("="*70 + "\n")

    if not no_browser:
        webbrowser.open(f'http://127.0.0.1:8080/{report_name}')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[âœ“] Server stopped.")


if __name__ == '__main__':
    main()