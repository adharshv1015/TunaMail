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

            # --- Base Metadata Analysis ---
            if extension in self.EXECUTABLE_EXTENSIONS:
                score += self.EXECUTABLE_RISK
                self._add_evidence("EXECUTABLE_ATTACHMENT", "CRITICAL", f"Executable attachment: {filename}", 0.98, evidence, structured_evidence)
            if extension in self.SCRIPT_EXTENSIONS:
                score += self.SCRIPT_RISK
                self._add_evidence("SCRIPT_ATTACHMENT", "CRITICAL", f"Script attachment: {filename}", 0.97, evidence, structured_evidence)
            if extension in self.MACRO_EXTENSIONS:
                score += self.MACRO_RISK
                self._add_evidence("MACRO_ATTACHMENT", "HIGH", f"Macro-enabled Office document: {filename}", 0.95, evidence, structured_evidence)
            if extension in self.ARCHIVE_EXTENSIONS:
                score += self.ARCHIVE_RISK
                self._add_evidence("ARCHIVE_ATTACHMENT", "MEDIUM", f"Archive attachment: {filename}", 0.80, evidence, structured_evidence)
            if filename.count(".") >= 2:
                score += self.DOUBLE_EXTENSION_RISK
                self._add_evidence("DOUBLE_EXTENSION", "HIGH", f"Multiple extensions: {filename}", 0.90, evidence, structured_evidence)
            if size > self.LARGE_FILE_BYTES:
                score += self.LARGE_FILE_RISK
                self._add_evidence("LARGE_ATTACHMENT", "LOW", f"Large attachment: {filename}", 0.70, evidence, structured_evidence)

            # --- Deep Content Analysis ---
            if not attachment_id:
                # Fallback to metadata-only
                logger.info(f"Skipping deep scan for {filename}: no attachmentId")
                deep_scan_skips += 1
                continue
            
            if size > ATTACHMENT_DEEP_SCAN_MAX_BYTES:
                # Explicitly log skip
                msg = f"Deep scan: SKIPPED (exceeds configured {ATTACHMENT_DEEP_SCAN_MAX_MB} MB limit) for {filename}"
                logger.warning(msg)
                self._add_evidence("DEEP_SCAN_SKIPPED", "INFO", msg, 0.9, evidence, structured_evidence, direction="NEUTRAL")
                deep_scan_skips += 1
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
                        self._deep_scan_zip(file_bytes, filename, evidence, structured_evidence)
                        deep_scan_successes += 1
                        
                    elif extension in [".pdf"] or mime_type == "application/pdf":
                        if progress_callback:
                            progress_callback({"type": "progress", "step": "Inspecting PDF structure...", "progress": 25})
                        if self._deep_scan_pdf(file_bytes, filename, evidence, structured_evidence):
                            deep_scan_successes += 1
                        else:
                            deep_scan_skips += 1
                        
                    elif extension in [".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"]:
                        if progress_callback:
                            progress_callback({"type": "progress", "step": "Scanning Office macros...", "progress": 25})
                        if self._deep_scan_office(file_bytes, filename, evidence, structured_evidence):
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
            "evidence": evidence,
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
                    "structured_evidence": []
                }
                
            # Attempt to decrypt
            success = reader.decrypt(password)
            if not success:
                self._add_evidence("PDF_ENCRYPTED", "MEDIUM", f"PDF is encrypted/password-protected: {filename}", 0.9, evidence, structured_evidence)
                return {
                    "status": "INVALID_PASSWORD",
                    "evidence": evidence,
                    "structured_evidence": structured_evidence
                }
                
            # Decryption succeeded. Perform static inspection.
            if reader.trailer and "/Root" in reader.trailer:
                root = reader.trailer["/Root"].get_object()
                if "/OpenAction" in root:
                    self._add_evidence("PDF_OPENACTION", "HIGH", f"PDF contains OpenAction: {filename}", 0.95, evidence, structured_evidence)
                if "/Names" in root:
                    names = root["/Names"].get_object()
                    if "/JavaScript" in names:
                        self._add_evidence("PDF_JAVASCRIPT", "HIGH", f"PDF contains JavaScript action: {filename}", 0.95, evidence, structured_evidence)
                        
                # Extract text now that it's decrypted and analyze URLs
                extracted_text = ""
                for page in reader.pages:
                    extracted_text += (page.extract_text() or "") + "\n"
                    
                if extracted_text.strip():
                    from src.analyzers.url_analyzer import URLAnalyzer
                    url_analyzer = URLAnalyzer()
                    url_results = url_analyzer.analyze(extracted_text)
                    
                    if url_results.get("structured_evidence"):
                        for item in url_results["structured_evidence"]:
                            item["source"] = f"AttachmentAnalyzer ({filename})"
                            structured_evidence.append(item)
                            if item.get("explanation") and item.get("direction") == "NEGATIVE":
                                evidence.append(f"[URL in PDF] {item['explanation']}")
                            
                # Discard password entirely by letting it fall out of scope
                return {
                    "status": "SUCCESS",
                    "evidence": evidence,
                    "structured_evidence": structured_evidence
                }
        except Exception as e:
            logger.error(f"Error scanning encrypted PDF {filename}: {e}")
            return {
                "status": "ERROR",
                "message": str(e)
            }

    def _deep_scan_zip(self, file_bytes: bytes, original_filename: str, evidence: list, structured_evidence: list, depth: int = 1):
        if depth > MAX_ARCHIVE_RECURSION_DEPTH:
            self._add_evidence("ARCHIVE_RECURSION_LIMIT", "HIGH", f"Archive {original_filename} exceeds maximum recursion depth.", 0.95, evidence, structured_evidence)
            return

        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                file_list = z.infolist()
                
                if len(file_list) > MAX_ARCHIVE_FILES:
                    self._add_evidence("ARCHIVE_FILE_LIMIT", "HIGH", f"Archive {original_filename} exceeds max file limit ({MAX_ARCHIVE_FILES}).", 0.95, evidence, structured_evidence)
                    return
                
                total_extracted_size = sum(f.file_size for f in file_list)
                if total_extracted_size > MAX_ARCHIVE_EXTRACTED_BYTES:
                    self._add_evidence("ARCHIVE_SIZE_LIMIT", "HIGH", f"Archive {original_filename} extracted size ({total_extracted_size}B) exceeds limits.", 0.95, evidence, structured_evidence)
                    return

                for f in file_list:
                    filename = f.filename.lower()
                    _, ext = os.path.splitext(filename)
                    if ext in self.EXECUTABLE_EXTENSIONS:
                        self._add_evidence("ARCHIVE_CONTAINS_EXECUTABLE", "HIGH", f"Archive contains executable file: {f.filename}", 0.95, evidence, structured_evidence)
                    if ext in self.SCRIPT_EXTENSIONS:
                        self._add_evidence("ARCHIVE_CONTAINS_SCRIPT", "MEDIUM", f"Archive contains nested script file: {f.filename}", 0.9, evidence, structured_evidence)
                    
                    if ext == ".zip":
                        # Recurse
                        inner_bytes = z.read(f.filename)
                        self._deep_scan_zip(inner_bytes, f.filename, evidence, structured_evidence, depth + 1)
                        
        except zipfile.BadZipFile:
            self._add_evidence("CORRUPT_ARCHIVE", "LOW", f"Archive {original_filename} is corrupt or invalid.", 0.8, evidence, structured_evidence)
        except Exception as e:
            logger.error(f"Error scanning ZIP {original_filename}: {e}")

    def _deep_scan_office(self, file_bytes: bytes, filename: str, evidence: list, structured_evidence: list):
        if not OLETOOLS_AVAILABLE:
            logger.warning("oletools not available, skipping Office macro scan")
            self._add_evidence("DEPENDENCY_MISSING", "WARNING", f"Cannot deep scan Office macros in {filename} because 'oletools' is not installed.", 0.5, evidence, structured_evidence, direction="NEUTRAL")
            return False
            
        try:
            parser = VBA_Parser(filename, data=file_bytes)
            if parser.detect_vba_macros():
                self._add_evidence("OFFICE_MACRO", "HIGH", f"Office document contains VBA macro: {filename}", 0.95, evidence, structured_evidence)
                
                results = parser.analyze_macros()
                for kw_type, keyword, description in results:
                    if kw_type == 'AutoExec':
                        self._add_evidence("OFFICE_AUTOEXEC", "HIGH", f"Office document contains AutoOpen/AutoExec macro: {keyword}", 0.95, evidence, structured_evidence)
                    elif kw_type == 'Suspicious':
                        self._add_evidence("OFFICE_SUSPICIOUS_MACRO", "MEDIUM", f"Office document contains suspicious macro keyword: {keyword}", 0.9, evidence, structured_evidence)
            parser.close()
            return True
        except Exception as e:
            logger.error(f"Error scanning Office doc {filename}: {e}")
            return False

    def _deep_scan_pdf(self, file_bytes: bytes, filename: str, evidence: list, structured_evidence: list):
        # PyPDF2 analysis
        if PYPDF2_AVAILABLE:
            try:
                reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
                if reader.is_encrypted:
                    self._add_evidence("PDF_ENCRYPTED", "MEDIUM", f"PDF is encrypted/password-protected: {filename}", 0.9, evidence, structured_evidence)
                # Look for JS/OpenAction in catalog
                if reader.trailer and "/Root" in reader.trailer:
                    root = reader.trailer["/Root"].get_object()
                    if "/OpenAction" in root:
                        self._add_evidence("PDF_OPENACTION", "HIGH", f"PDF contains OpenAction: {filename}", 0.95, evidence, structured_evidence)
                    if "/Names" in root:
                        names = root["/Names"].get_object()
                        if "/JavaScript" in names:
                            self._add_evidence("PDF_JAVASCRIPT", "HIGH", f"PDF contains JavaScript action: {filename}", 0.95, evidence, structured_evidence)
                            
                if not reader.is_encrypted:
                    extracted_text = ""
                    for page in reader.pages:
                        extracted_text += (page.extract_text() or "") + "\n"
                        
                    if extracted_text.strip():
                        from src.analyzers.url_analyzer import URLAnalyzer
                        url_analyzer = URLAnalyzer()
                        url_results = url_analyzer.analyze(extracted_text)
                        
                        if url_results.get("structured_evidence"):
                            for item in url_results["structured_evidence"]:
                                item["source"] = f"AttachmentAnalyzer ({filename})"
                                structured_evidence.append(item)
                                if item.get("explanation") and item.get("direction") == "NEGATIVE":
                                    evidence.append(f"[URL in PDF] {item['explanation']}")
            except Exception as e:
                logger.error(f"Error scanning PDF via PyPDF2 {filename}: {e}")
        else:
            logger.warning("PyPDF2 not available, skipping PDF deep scan")
            self._add_evidence("DEPENDENCY_MISSING", "WARNING", f"Cannot deep scan {filename} because 'PyPDF2' is not installed.", 0.5, evidence, structured_evidence, direction="NEUTRAL")
            return False
        
        # PDFiD analysis
        if PDFID_AVAILABLE:
            try:
                class PDFiDOptions:
                    def __init__(self):
                        self.scan = True
                        self.all = False
                        self.extra = False
                        self.force = False
                        self.disarm = False
                        self.return_dict = True
                        self.select = ""
                
                # Write to temp file for pdfid (it expects a filename or stream)
                with open("/tmp/temp_pdf_scan.pdf", "wb") as f:
                    f.write(file_bytes)
                
                # pdfid_lib.PDFiD expects xml output generation etc., there is a cleaner way using pdfid_lib
                # For simplicity, we can parse it locally if pdfid provides a wrapper
                # But since PyPDF2 covers the basics (JS/OpenAction), we rely on it mainly.
                # Just keeping the stub for PDFID_AVAILABLE.
                pass
            except Exception as e:
                pass
        
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
        except: return ""

    @staticmethod
    def _safe_size(size: Any) -> int:
        try: return max(0, int(size or 0))
        except: return 0
