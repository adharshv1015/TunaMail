import logging
import os
import io
import base64
import zipfile
from typing import Any, Dict, Iterable, List

try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False

try:
    import PyPDF2
    PYPDF2_AVAILABLE = True
except ImportError:
    PYPDF2_AVAILABLE = False

try:
    import pdfid.pdfid as pdfid_lib
    PDFID_AVAILABLE = True
except ImportError:
    PDFID_AVAILABLE = False


logger = logging.getLogger(__name__)


# Configuration limits
ATTACHMENT_DEEP_SCAN_MAX_MB = int(os.environ.get("ATTACHMENT_DEEP_SCAN_MAX_MB", "100"))
ATTACHMENT_DEEP_SCAN_MAX_BYTES = ATTACHMENT_DEEP_SCAN_MAX_MB * 1024 * 1024

MAX_ARCHIVE_FILES = int(os.environ.get("MAX_ARCHIVE_FILES", "10000"))
MAX_ARCHIVE_EXTRACTED_MB = int(os.environ.get("MAX_ARCHIVE_EXTRACTED_MB", "500"))
MAX_ARCHIVE_EXTRACTED_BYTES = MAX_ARCHIVE_EXTRACTED_MB * 1024 * 1024
MAX_ARCHIVE_RECURSION_DEPTH = int(os.environ.get("MAX_ARCHIVE_RECURSION_DEPTH", "3"))


class AttachmentAnalyzer:
    """
    Defensive attachment security analyzer.

    Produces deterministic attachment evidence via deep content inspection.
    """

    EXECUTABLE_EXTENSIONS = {".exe", ".msi", ".bat", ".cmd", ".scr", ".com"}
    SCRIPT_EXTENSIONS = {".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1", ".hta"}
    MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
    ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso"}

    DOUBLE_EXTENSION_RISK = 15
    LARGE_FILE_RISK = 5
    EXECUTABLE_RISK = 40
    SCRIPT_RISK = 35
    MACRO_RISK = 30
    ARCHIVE_RISK = 15
    LARGE_FILE_BYTES = 10 * 1024 * 1024

    def analyze(
        self,
        attachments: Iterable[Dict[str, Any]] | None,
        connector=None,
        message_id=None,
        progress_callback=None,
    ) -> Dict[str, Any]:
        """
        Analyze attachments using metadata and local deep scanning.
        """
        if attachments is None:
            attachments = []
        if not isinstance(attachments, (list, tuple)):
            attachments = []

        score = 0
        evidence: List[str] = []
        structured_evidence: List[Dict[str, Any]] = []
        analyzed_count = 0
        
        deep_scan_successes = 0
        deep_scan_skips = 0
        deep_scan_failures = 0

        files: List[Dict[str, Any]] = []

        for attachment in attachments:
            if not isinstance(attachment, dict):
                continue

            filename = self._normalize_filename(attachment.get("filename"))
            if not filename:
                continue

            size = self._safe_size(attachment.get("size", 0))
            attachment_id = attachment.get("attachmentId")
            mime_type = attachment.get("mimeType", "").lower()
            
            analyzed_count += 1
            filename_lower = filename.lower()
            _, extension = os.path.splitext(filename_lower)

            file_entry: Dict[str, Any] = {
                "filename": filename,
                "size": size,
                "attachmentId": attachment_id,
                "mimeType": mime_type,
                "extension": extension,
                "risk_score": 0,
                "is_encrypted_pdf": False,
                "is_macro": False,
                "malicious": False,
                "issues": [],
                "unsafe_urls": [],
            }

            # --- Base Metadata Analysis ---
            if extension in self.EXECUTABLE_EXTENSIONS:
                score += self.EXECUTABLE_RISK
                file_entry["risk_score"] = max(file_entry["risk_score"], 85)
                file_entry["malicious"] = True
                file_entry["issues"].append(f"Executable binary file: {filename}")
                self._add_evidence("EXECUTABLE_ATTACHMENT", "CRITICAL", f"Executable attachment: {filename}", 0.98, evidence, structured_evidence)
            if extension in self.SCRIPT_EXTENSIONS:
                score += self.SCRIPT_RISK
                file_entry["risk_score"] = max(file_entry["risk_score"], 75)
                file_entry["malicious"] = True
                file_entry["issues"].append(f"Script file: {filename}")
                self._add_evidence("SCRIPT_ATTACHMENT", "CRITICAL", f"Script attachment: {filename}", 0.97, evidence, structured_evidence)
            if extension in self.MACRO_EXTENSIONS:
                score += self.MACRO_RISK
                file_entry["is_macro"] = True
                file_entry["risk_score"] = max(file_entry["risk_score"], 60)
                file_entry["issues"].append(f"Macro-enabled document format: {filename}")
                self._add_evidence("MACRO_ATTACHMENT", "HIGH", f"Macro-enabled Office document: {filename}", 0.95, evidence, structured_evidence)
            if extension in self.ARCHIVE_EXTENSIONS:
                score += self.ARCHIVE_RISK
                file_entry["risk_score"] = max(file_entry["risk_score"], 30)
                self._add_evidence("ARCHIVE_ATTACHMENT", "MEDIUM", f"Archive attachment: {filename}", 0.80, evidence, structured_evidence)
            if filename.count(".") >= 2:
                score += self.DOUBLE_EXTENSION_RISK
                file_entry["risk_score"] = max(file_entry["risk_score"], 50)
                file_entry["issues"].append(f"Multiple file extensions detected: {filename}")
                self._add_evidence("DOUBLE_EXTENSION", "HIGH", f"Multiple extensions: {filename}", 0.90, evidence, structured_evidence)
            if size > self.LARGE_FILE_BYTES:
                score += self.LARGE_FILE_RISK
                self._add_evidence("LARGE_ATTACHMENT", "LOW", f"Large attachment: {filename}", 0.70, evidence, structured_evidence)

            # --- Deep Content Analysis ---
            if not attachment_id:
                # Fallback to metadata-only
                logger.info(f"Skipping deep scan for {filename}: no attachmentId")
                deep_scan_skips += 1
                files.append(file_entry)
                continue
            
            if size > ATTACHMENT_DEEP_SCAN_MAX_BYTES:
                # Explicitly log skip
                msg = f"Deep scan: SKIPPED (exceeds configured {ATTACHMENT_DEEP_SCAN_MAX_MB} MB limit) for {filename}"
                logger.warning(msg)
                self._add_evidence("DEEP_SCAN_SKIPPED", "INFO", msg, 0.9, evidence, structured_evidence, direction="NEUTRAL")
                deep_scan_skips += 1
                files.append(file_entry)
                continue

            if connector and message_id:
                try:
                    if progress_callback:
                        progress_callback({"type": "progress", "step": "Downloading attachment...", "progress": 20})
                    
                    raw_attachment = connector.get_attachment(message_id, attachment_id)
                    data = raw_attachment.get("data", "")
                    file_bytes = base64.urlsafe_b64decode(data)
                    
                    if extension == ".zip" or mime_type in ["application/zip", "application/x-zip-compressed"]:
                        if progress_callback:
                            progress_callback({"type": "progress", "step": "Inspecting archive...", "progress": 25})
                        self._deep_scan_zip(file_bytes, filename, evidence, structured_evidence, file_entry=file_entry)
                        deep_scan_successes += 1
                        
                    elif extension in [".pdf"] or mime_type == "application/pdf":
                        if progress_callback:
                            progress_callback({"type": "progress", "step": "Inspecting PDF structure...", "progress": 25})
                        if self._deep_scan_pdf(file_bytes, filename, evidence, structured_evidence, file_entry=file_entry):
                            deep_scan_successes += 1
                        else:
                            deep_scan_skips += 1
                        
                    elif extension in [".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"]:
                        if progress_callback:
                            progress_callback({"type": "progress", "step": "Scanning Office macros...", "progress": 25})
                        if self._deep_scan_office(file_bytes, filename, evidence, structured_evidence, file_entry=file_entry):
                            deep_scan_successes += 1
                        else:
                            deep_scan_skips += 1
                    else:
                        # Unscannable extension
                        deep_scan_skips += 1
                        
                except Exception as e:
                    logger.error(f"Error during deep scan of {filename}: {e}", exc_info=True)
                    self._add_evidence("DEEP_SCAN_ERROR", "INFO", f"Failed to deep scan {filename}", 0.5, evidence, structured_evidence, direction="NEUTRAL")
                    deep_scan_failures += 1

            score = max(score, file_entry["risk_score"])
            files.append(file_entry)

        score = max(0, min(int(score), 100))

        if progress_callback:
            progress_callback({"type": "progress", "step": "Deep attachment scan complete", "progress": 30})

        if len(attachments) > 0 and deep_scan_successes == len(attachments) and deep_scan_skips == 0 and deep_scan_failures == 0:
            self._add_evidence(
                "ALL_ATTACHMENTS_DEEP_SCAN_COMPLETED", 
                "INFO", 
                "Every applicable attachment was successfully deep scanned without failures or skips.", 
                0.95, 
                evidence, 
                structured_evidence,
                direction="POSITIVE"
            )

        return {
            "analysis_status": "AVAILABLE",
            "attachment_count": len(attachments),
            "analyzed_attachment_count": analyzed_count,
            "risk_score": score,
            "files": files,
            "evidence": evidence,
            "structured_evidence": structured_evidence,
        }

    # ------------------------------------------------------------------
    # Shared helper: extract URLs from a decrypted PyPDF2 reader
    # and run them through the FULL URLAnalyzer pipeline.
    # Filters and surfaces ONLY unsafe/phishing URLs for attachment view.
    # ------------------------------------------------------------------
    def _analyze_pdf_urls(
        self,
        reader,
        filename: str,
        evidence: list,
        structured_evidence: list,
    ) -> dict:
        """
        Extract URLs from text + annotations of a decrypted PDF reader,
        run each through the full URLAnalyzer pipeline (homograph, TLS,
        brand checks, keyword detection, etc.) and surface evidence.
        """
        from src.analyzers.url_analyzer import URLAnalyzer
        url_analyzer = URLAnalyzer()

        # --- 1. URLs from page text ---
        extracted_text = ""
        for page in reader.pages:
            extracted_text += (page.extract_text() or "") + "\n"

        text_urls = url_analyzer.extract_urls(extracted_text) if extracted_text.strip() else []

        # --- 2. URLs from PDF annotation objects (clickable links) ---
        annotation_urls = []
        try:
            for page in reader.pages:
                if "/Annots" not in page:
                    continue
                annots = page["/Annots"]
                if hasattr(annots, "get_object"):
                    annots = annots.get_object()
                for annot in (annots or []):
                    try:
                        obj = annot.get_object() if hasattr(annot, "get_object") else annot
                        if not isinstance(obj, dict):
                            continue
                        subtype = obj.get("/Subtype", "")
                        if str(subtype) != "/Link":
                            continue
                        action = obj.get("/A")
                        if action is None:
                            continue
                        if hasattr(action, "get_object"):
                            action = action.get_object()
                        uri = action.get("/URI", "")
                        if uri:
                            uri_str = str(uri)
                            normalized = url_analyzer._normalize_url(uri_str)
                            if url_analyzer._is_http_url(normalized):
                                annotation_urls.append(normalized)
                    except Exception:
                        continue
        except Exception as _ann_exc:
            logger.debug(f"PDF annotation extraction failed for {filename}: {_ann_exc}")

        # Merge and deduplicate
        all_urls = list(dict.fromkeys(text_urls + annotation_urls))

        if not all_urls:
            return {}

        logger.info(
            "PDF '%s': found %d URL(s) (%d from text, %d from annotations)",
            filename, len(all_urls), len(text_urls), len(annotation_urls),
        )

        # --- 3. Run every URL through the FULL analyze_url pipeline ---
        url_results_list = []
        for url in all_urls[:15]:  # cap at 15 to avoid timeout
            try:
                res = url_analyzer.analyze_url(url)
                res["source"] = "PDF Attachment"
                res["pdf_source"] = (
                    "annotation" if url in annotation_urls else "text"
                )
                url_results_list.append(res)

                # Collect structured evidence from each URL
                for ev in res.get("structured_evidence", []):
                    ev_copy = dict(ev)
                    ev_copy["source"] = f"AttachmentAnalyzer ({filename})"
                    structured_evidence.append(ev_copy)
                    if ev_copy.get("direction") == "NEGATIVE" and ev_copy.get("explanation"):
                        evidence.append(f"[URL in PDF] {ev_copy['explanation']}")

                # Surface critical indicators as top-level attachment evidence
                for ev in res.get("structured_evidence", []):
                    t = ev.get("type", "")
                    if t in (
                        "UNICODE_HOMOGRAPH_BRAND_SPOOF",
                        "BRAND_IMPERSONATION",
                        "HOMOGRAPH_DOMAIN",
                    ):
                        self._add_evidence(
                            t, "CRITICAL",
                            f"[PDF Link] {ev.get('explanation', '')}",
                            float(ev.get("confidence", 0.95)),
                            evidence, structured_evidence,
                        )
                    elif t in (
                        "UNICODE_MIXED_SCRIPT_DOMAIN",
                        "UNICODE_NON_ASCII_DOMAIN",
                        "PUNYCODE_DOMAIN",
                        "TLS_POLICY_VIOLATION",
                    ):
                        self._add_evidence(
                            t, "HIGH",
                            f"[PDF Link] {ev.get('explanation', '')}",
                            float(ev.get("confidence", 0.90)),
                            evidence, structured_evidence,
                        )
            except Exception as _url_exc:
                logger.warning(f"URL analysis failed for {url} in {filename}: {_url_exc}")

        # Extract ONLY unsafe/phishing URLs for the attachment issues tab
        unsafe_urls = []
        for res in url_results_list:
            url_str = res.get("url") or ""
            u_score = res.get("risk_score", 0)
            u_rep = (res.get("reputation") or "").upper()
            u_brand = bool(
                res.get("brand_impersonation")
                or res.get("brand_relationship") in ("LOOKALIKE", "IMPERSONATION")
            )

            neg_evs = [
                ev for ev in res.get("structured_evidence", [])
                if ev.get("direction") == "NEGATIVE"
                or ev.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
            ]

            has_homograph = any(
                ev.get("type") in (
                    "UNICODE_HOMOGRAPH_BRAND_SPOOF",
                    "HOMOGRAPH_DOMAIN",
                    "UNICODE_MIXED_SCRIPT_DOMAIN",
                    "UNICODE_NON_ASCII_DOMAIN",
                    "PUNYCODE_DOMAIN",
                )
                for ev in neg_evs
            )

            is_phishing = u_brand or u_rep == "MALICIOUS" or has_homograph or u_score >= 60
            is_unsafe = (
                is_phishing
                or u_rep == "SUSPICIOUS"
                or u_score >= 30
                or len(neg_evs) > 0
                or res.get("has_strong_negative_evidence")
                or res.get("http_policy_warning")
                or any(ev.get("type") == "TLS_POLICY_VIOLATION" for ev in neg_evs)
            )

            if is_phishing or is_unsafe:
                reasons = []
                for ev in neg_evs:
                    exp = ev.get("explanation")
                    if exp and exp not in reasons:
                        reasons.append(exp)
                if not reasons and res.get("threat_intelligence", {}).get("summary"):
                    reasons.append(res["threat_intelligence"]["summary"])
                if not reasons and u_brand:
                    reasons.append("Brand impersonation / lookalike domain")
                if not reasons and url_str.startswith("http://"):
                    reasons.append("Insecure HTTP transport")

                unsafe_urls.append({
                    "url": url_str,
                    "domain": res.get("domain") or res.get("registered_domain") or "",
                    "verdict": "PHISHING" if is_phishing else "SUSPICIOUS",
                    "risk_score": max(u_score, 85 if is_phishing else 50),
                    "is_phishing": is_phishing,
                    "reasons": reasons,
                    "brand_impersonation": u_brand,
                    "has_homograph": has_homograph,
                })

        # Aggregate risk score
        url_risk = 0
        for u in unsafe_urls:
            url_risk = max(url_risk, u["risk_score"])
        for res in url_results_list:
            for ev in res.get("structured_evidence", []):
                sev = ev.get("severity", "")
                if sev == "CRITICAL":
                    url_risk = max(url_risk, 90)
                elif sev == "HIGH":
                    url_risk = max(url_risk, 70)
                elif sev == "MEDIUM":
                    url_risk = max(url_risk, 40)

        if url_risk > 0:
            self._add_evidence(
                "PDF_URL_RISK",
                "HIGH" if url_risk >= 70 else "MEDIUM",
                f"URL analysis of PDF '{filename}' returned risk score {url_risk}/100.",
                min(0.95, 0.4 + url_risk / 200),
                evidence, structured_evidence,
            )

        return {
            "analysis_status": "AVAILABLE",
            "urls": all_urls,
            "count": len(all_urls),
            "analysis": url_results_list,
            "unsafe_urls": unsafe_urls,
            "risk_score": url_risk,
            "structured_evidence": structured_evidence,
        }

    def analyze_encrypted_pdf(self, file_bytes: bytes, filename: str, password: str) -> Dict[str, Any]:
        """
        Temporarily decrypt and deeply scan a password-protected PDF in memory.
        Does not log or persist the password.
        """
        evidence = []
        structured_evidence = []
        
        if not PYPDF2_AVAILABLE:
            return {
                "status": "ERROR",
                "message": "PyPDF2 is not installed."
            }
            
        try:
            reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
            
            if not reader.is_encrypted:
                return {
                    "status": "ALREADY_DECRYPTED",
                    "evidence": [],
                    "structured_evidence": [],
                    "unsafe_urls": [],
                    "issues": [],
                    "risk_score": 0,
                }
                
            # Attempt to decrypt
            success = reader.decrypt(password)
            if not success:
                self._add_evidence("PDF_ENCRYPTED", "MEDIUM", f"PDF is encrypted/password-protected: {filename}", 0.9, evidence, structured_evidence)
                return {
                    "status": "INVALID_PASSWORD",
                    "evidence": evidence,
                    "structured_evidence": structured_evidence,
                    "unsafe_urls": [],
                    "issues": ["Password-protected PDF container preventing static inspection."],
                    "risk_score": 30,
                }
                
            # Decryption succeeded. Perform static inspection.
            issues = []
            if reader.trailer and "/Root" in reader.trailer:
                root = reader.trailer["/Root"].get_object()
                if "/OpenAction" in root:
                    issues.append("PDF contains OpenAction launch trigger")
                    self._add_evidence("PDF_OPENACTION", "HIGH", f"PDF contains OpenAction: {filename}", 0.95, evidence, structured_evidence)
                if "/Names" in root:
                    names = root["/Names"].get_object()
                    if "/JavaScript" in names:
                        issues.append("PDF contains embedded JavaScript action")
                        self._add_evidence("PDF_JAVASCRIPT", "HIGH", f"PDF contains JavaScript action: {filename}", 0.95, evidence, structured_evidence)

            # Full URL analysis: text + annotation links, full pipeline
            pdf_url_analysis = self._analyze_pdf_urls(reader, filename, evidence, structured_evidence)
            unsafe_urls = pdf_url_analysis.get("unsafe_urls", []) if pdf_url_analysis else []
            pdf_risk = pdf_url_analysis.get("risk_score", 0) if pdf_url_analysis else 0

            for u in unsafe_urls:
                reason_text = f" ({u['reasons'][0]})" if u.get("reasons") else ""
                issues.append(f"{u.get('verdict', 'UNSAFE')} link found in PDF: {u.get('url', '')}{reason_text}")

            return {
                "status": "SUCCESS",
                "evidence": evidence,
                "structured_evidence": structured_evidence,
                "pdf_url_analysis": pdf_url_analysis if pdf_url_analysis else None,
                "unsafe_urls": unsafe_urls,
                "issues": issues,
                "risk_score": pdf_risk,
                "malicious": any(u.get("is_phishing") for u in unsafe_urls),
                "is_encrypted_pdf": False,
            }
        except Exception as e:
            logger.error(f"Error scanning encrypted PDF {filename}: {e}")
            err_str = str(e).lower()
            if "wrong password" in err_str or "password is incorrect" in err_str or "cannot decrypt" in err_str:
                return {
                    "status": "INVALID_PASSWORD",
                    "evidence": evidence,
                    "structured_evidence": structured_evidence,
                    "unsafe_urls": [],
                    "issues": ["Password-protected PDF container."],
                    "risk_score": 30,
                }
            return {
                "status": "ERROR",
                "message": str(e),
                "unsafe_urls": [],
                "issues": [],
                "risk_score": 0,
            }

    def _deep_scan_zip(self, file_bytes: bytes, original_filename: str, evidence: list, structured_evidence: list, depth: int = 1, file_entry: dict = None):
        if depth > MAX_ARCHIVE_RECURSION_DEPTH:
            self._add_evidence("ARCHIVE_RECURSION_LIMIT", "HIGH", f"Archive {original_filename} exceeds maximum recursion depth.", 0.95, evidence, structured_evidence)
            if file_entry is not None:
                file_entry["issues"].append("Archive exceeds maximum recursion depth limit")
            return

        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                file_list = z.infolist()
                
                if len(file_list) > MAX_ARCHIVE_FILES:
                    self._add_evidence("ARCHIVE_FILE_LIMIT", "HIGH", f"Archive {original_filename} exceeds max file limit ({MAX_ARCHIVE_FILES}).", 0.95, evidence, structured_evidence)
                    if file_entry is not None:
                        file_entry["issues"].append(f"Archive exceeds max file limit ({MAX_ARCHIVE_FILES})")
                    return
                
                total_extracted_size = sum(f.file_size for f in file_list)
                if total_extracted_size > MAX_ARCHIVE_EXTRACTED_BYTES:
                    self._add_evidence("ARCHIVE_SIZE_LIMIT", "HIGH", f"Archive {original_filename} extracted size ({total_extracted_size}B) exceeds limits.", 0.95, evidence, structured_evidence)
                    if file_entry is not None:
                        file_entry["issues"].append(f"Archive extracted size exceeds limits")
                    return

                for f in file_list:
                    filename = f.filename.lower()
                    _, ext = os.path.splitext(filename)
                    if ext in self.EXECUTABLE_EXTENSIONS:
                        self._add_evidence("ARCHIVE_CONTAINS_EXECUTABLE", "HIGH", f"Archive contains executable file: {f.filename}", 0.95, evidence, structured_evidence)
                        if file_entry is not None:
                            file_entry["risk_score"] = max(file_entry["risk_score"], 85)
                            file_entry["malicious"] = True
                            file_entry["issues"].append(f"Archive contains executable: {f.filename}")
                    if ext in self.SCRIPT_EXTENSIONS:
                        self._add_evidence("ARCHIVE_CONTAINS_SCRIPT", "MEDIUM", f"Archive contains nested script file: {f.filename}", 0.9, evidence, structured_evidence)
                        if file_entry is not None:
                            file_entry["risk_score"] = max(file_entry["risk_score"], 70)
                            file_entry["issues"].append(f"Archive contains script: {f.filename}")
                    
                    if ext == ".zip":
                        # Recurse
                        inner_bytes = z.read(f.filename)
                        self._deep_scan_zip(inner_bytes, f.filename, evidence, structured_evidence, depth + 1, file_entry=file_entry)
                        
        except zipfile.BadZipFile:
            self._add_evidence("CORRUPT_ARCHIVE", "LOW", f"Archive {original_filename} is corrupt or invalid.", 0.8, evidence, structured_evidence)
            if file_entry is not None:
                file_entry["issues"].append("Corrupt or invalid archive container")
        except Exception as e:
            logger.error(f"Error scanning ZIP {original_filename}: {e}")

    def _deep_scan_office(self, file_bytes: bytes, filename: str, evidence: list, structured_evidence: list, file_entry: dict = None):
        if not OLETOOLS_AVAILABLE:
            logger.warning("oletools not available, skipping Office macro scan")
            self._add_evidence("DEPENDENCY_MISSING", "WARNING", f"Cannot deep scan Office macros in {filename} because 'oletools' is not installed.", 0.5, evidence, structured_evidence, direction="NEUTRAL")
            return False
            
        try:
            parser = VBA_Parser(filename, data=file_bytes)
            if parser.detect_vba_macros():
                self._add_evidence("OFFICE_MACRO", "HIGH", f"Office document contains VBA macro: {filename}", 0.95, evidence, structured_evidence)
                if file_entry is not None:
                    file_entry["is_macro"] = True
                    file_entry["risk_score"] = max(file_entry["risk_score"], 80)
                    file_entry["malicious"] = True
                    file_entry["issues"].append("Active VBA macros detected in Office document")
                
                results = parser.analyze_macros()
                for kw_type, keyword, description in results:
                    if kw_type == 'AutoExec':
                        self._add_evidence("OFFICE_AUTOEXEC", "HIGH", f"Office document contains AutoOpen/AutoExec macro: {keyword}", 0.95, evidence, structured_evidence)
                        if file_entry is not None:
                            file_entry["issues"].append(f"Auto-execution macro detected: {keyword}")
                    elif kw_type == 'Suspicious':
                        self._add_evidence("OFFICE_SUSPICIOUS_MACRO", "MEDIUM", f"Office document contains suspicious macro keyword: {keyword}", 0.9, evidence, structured_evidence)
                        if file_entry is not None:
                            file_entry["issues"].append(f"Suspicious macro instruction: {keyword}")
            parser.close()
            return True
        except Exception as e:
            logger.error(f"Error scanning Office doc {filename}: {e}")
            return False

    def _deep_scan_pdf(self, file_bytes: bytes, filename: str, evidence: list, structured_evidence: list, file_entry: dict = None):
        # PyPDF2 analysis
        if PYPDF2_AVAILABLE:
            try:
                reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
                if reader.is_encrypted:
                    self._add_evidence("PDF_ENCRYPTED", "MEDIUM", f"PDF is encrypted/password-protected: {filename}", 0.9, evidence, structured_evidence)
                    if file_entry is not None:
                        file_entry["is_encrypted_pdf"] = True
                        file_entry["risk_score"] = max(file_entry["risk_score"], 30)
                        file_entry["issues"].append("Password-encrypted PDF container preventing static inspection")
                else:
                    # Look for JS/OpenAction in catalog
                    if reader.trailer and "/Root" in reader.trailer:
                        root = reader.trailer["/Root"].get_object()
                        if "/OpenAction" in root:
                            self._add_evidence("PDF_OPENACTION", "HIGH", f"PDF contains OpenAction: {filename}", 0.95, evidence, structured_evidence)
                            if file_entry is not None:
                                file_entry["issues"].append("PDF contains OpenAction trigger")
                        if "/Names" in root:
                            names = root["/Names"].get_object()
                            if "/JavaScript" in names:
                                self._add_evidence("PDF_JAVASCRIPT", "HIGH", f"PDF contains JavaScript action: {filename}", 0.95, evidence, structured_evidence)
                                if file_entry is not None:
                                    file_entry["issues"].append("PDF contains embedded JavaScript action")

                    # Full URL analysis: text + annotation links, full pipeline
                    pdf_url_analysis = self._analyze_pdf_urls(reader, filename, evidence, structured_evidence)
                    if file_entry is not None and pdf_url_analysis:
                        unsafe_urls = pdf_url_analysis.get("unsafe_urls", [])
                        file_entry["unsafe_urls"] = unsafe_urls
                        if unsafe_urls:
                            url_risk = pdf_url_analysis.get("risk_score", 0)
                            file_entry["risk_score"] = max(file_entry["risk_score"], url_risk)
                            file_entry["malicious"] = any(u.get("is_phishing") for u in unsafe_urls)
                            for u in unsafe_urls:
                                reason_text = f" ({u['reasons'][0]})" if u['reasons'] else ""
                                file_entry["issues"].append(f"{u['verdict']} link in PDF: {u['url']}{reason_text}")

            except Exception as e:
                logger.error(f"Error scanning PDF via PyPDF2 {filename}: {e}")
        else:
            logger.warning("PyPDF2 not available, skipping PDF deep scan")
            self._add_evidence("DEPENDENCY_MISSING", "WARNING", f"Cannot deep scan {filename} because 'PyPDF2' is not installed.", 0.5, evidence, structured_evidence, direction="NEUTRAL")
            return False
        
        return True

    def _add_evidence(self, type_: str, severity: str, explanation: str, confidence: float, evidence_list: list, structured_list: list, direction: str = "NEGATIVE"):
        if direction != "POSITIVE":
            evidence_list.append(explanation)
        structured_list.append({
            "type": str(type_).strip().upper().replace("-", "_").replace(" ", "_"),
            "severity": str(severity).strip().upper(),
            "direction": direction,
            "source": "AttachmentAnalyzer",
            "explanation": str(explanation),
            "confidence": float(confidence),
        })

    # Keep old helpers for compatibility
    @staticmethod
    def _normalize_filename(filename: Any) -> str:
        if filename is None: return ""
        try: return str(filename).strip()
        except Exception: return ""

    @staticmethod
    def _safe_size(size: Any) -> int:
        try: return max(0, int(size or 0))
        except Exception: return 0
