from src.tests.test_stage7_evidence import TestStage7Evidence

test = TestStage7Evidence()
test.setUp()
mock = test.create_mock("Test <test@test.com>", "SECURE ENCRYPTED SAFE PROTECTED 100% VIRUS FREE Microsoft login https://ms-fake.com")
res = test.run_pipeline(mock)
print("VERDICT:", res["verdict"])
print("DETAIL VERDICT:", res["detail_verdict"])
print("RISK SCORE:", res["risk_score"])
print("CONFIDENCE:", res["confidence"])
print("EXPLANATION:", res["explanation"])
print("REASONING:", res.get("reasoning", {}))
