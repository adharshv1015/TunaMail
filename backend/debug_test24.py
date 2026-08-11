from src.tests.test_stage7_evidence import TestStage7Evidence

test = TestStage7Evidence()
test.setUp()
mock = test.create_mock("User <u@a.com>", "Hey", auth_pass=False)
res = test.run_pipeline(mock)
print("VERDICT:", res["verdict"])
print("DETAIL VERDICT:", res["detail_verdict"])
print("RISK SCORE:", res["risk_score"])
print("CONFIDENCE:", res["confidence"])
print("EXPLANATION:", res["explanation"])
print("REASONING:", res.get("reasoning", {}))
