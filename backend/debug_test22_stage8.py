from src.tests.test_stage8_behavioral import TestStage8Behavioral

test = TestStage8Behavioral()
test.setUpClass()
test.setUp()
test.build_reputation("trust22@test.com", 20, "LEGITIMATE")
mock = test.create_mock("trust22@test.com", "URGENT password reset required immediately. Click here http://malicious.com")
res = test.run_pipeline(mock)
print("VERDICT:", res["verdict"])
print("DETAIL VERDICT:", res["detail_verdict"])
print("REASONING:", res.get("reasoning", {}))
