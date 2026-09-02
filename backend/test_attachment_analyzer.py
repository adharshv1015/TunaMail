import os
import base64
import zipfile
import io
import json
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.analyzers.attachment_analyzer import AttachmentAnalyzer

# Mock Connector
class MockConnector:
    def __init__(self, data_bytes: bytes):
        self.data_bytes = data_bytes

    def get_attachment(self, message_id, attachment_id):
        return {
            "size": len(self.data_bytes),
            "data": base64.urlsafe_b64encode(self.data_bytes).decode('utf-8')
        }

# 1. Benign Attachment (illam.mp4)
benign_bytes = b"Just some video data"
analyzer = AttachmentAnalyzer()
result1 = analyzer.analyze(
    [{"filename": "illam.mp4", "size": len(benign_bytes), "attachmentId": "1", "mimeType": "video/mp4"}],
    connector=MockConnector(benign_bytes),
    message_id="msg1"
)
print("=== Benign Attachment (illam.mp4) ===")
print(json.dumps(result1["structured_evidence"], indent=2))
print("Score:", result1["risk_score"])

# 2. Oversized File (> 100MB)
oversized_size = 101 * 1024 * 1024
result2 = analyzer.analyze(
    [{"filename": "huge.zip", "size": oversized_size, "attachmentId": "2", "mimeType": "application/zip"}],
    connector=MockConnector(b"fake data"),
    message_id="msg2"
)
print("\n=== Oversized File (huge.zip) ===")
print(json.dumps(result2["structured_evidence"], indent=2))
print("Score:", result2["risk_score"])

# 3. Malicious PDF
malicious_pdf = b"""%PDF-1.7
1 0 obj
<< /Type /Catalog /OpenAction 2 0 R >>
endobj
2 0 obj
<< /Type /Action /S /JavaScript /JS (app.alert("Hello");) >>
endobj
trailer
<< /Root 1 0 R >>
%%EOF"""

result3 = analyzer.analyze(
    [{"filename": "invoice.pdf", "size": len(malicious_pdf), "attachmentId": "3", "mimeType": "application/pdf"}],
    connector=MockConnector(malicious_pdf),
    message_id="msg3"
)
print("\n=== Malicious PDF (invoice.pdf) ===")
print(json.dumps(result3["structured_evidence"], indent=2))
print("Score:", result3["risk_score"])

# 4. ZIP containing an executable
zip_buffer = io.BytesIO()
with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("hidden_malware.exe", b"MZ...")
    z.writestr("benign.txt", b"Hello world")
zip_bytes = zip_buffer.getvalue()

result4 = analyzer.analyze(
    [{"filename": "documents.zip", "size": len(zip_bytes), "attachmentId": "4", "mimeType": "application/zip"}],
    connector=MockConnector(zip_bytes),
    message_id="msg4"
)
print("\n=== Malicious ZIP (documents.zip) ===")
print(json.dumps(result4["structured_evidence"], indent=2))
print("Score:", result4["risk_score"])
