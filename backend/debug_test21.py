from src.tests.test_stage7_evidence import TestStage7Evidence
import pprint

test = TestStage7Evidence()
test.setUpClass()
test.setUp()
mock = test.create_mock("test@test.com", "")
auth_analysis = test.auth_analyzer.analyze(mock.get("headers", []))
url_analysis = test.url_analyzer.analyze(mock.get("body", ""), sender_headers=mock.get("headers", []), auth_results=auth_analysis)
trust_analysis = test.trust_analyzer.evaluate(parsed_email=mock, url_analysis=url_analysis)
content_analysis = test.content_analyzer.analyze(
    body=mock.get("body", ""),
    sender=mock.get("from", ""),
    auth_results=auth_analysis
)
attachment_analysis = test.attachment_analyzer.analyze(mock.get("attachments", []))

existing_analysis = {
    "authentication": auth_analysis,
    "content": content_analysis,
    "url": url_analysis,
    "whois": [],
    "attachment": attachment_analysis,
    "trust": trust_analysis
}

from src.ai.orchestrator import analyze_email_with_ai
ai_analysis = analyze_email_with_ai(mock, existing_analysis)
print("CALIBRATOR OUTPUT:", ai_analysis.get("confidence_calibration"))
