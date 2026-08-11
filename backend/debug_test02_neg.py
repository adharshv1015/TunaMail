from src.tests.test_stage8_behavioral import TestStage8Behavioral

test = TestStage8Behavioral()
test.setUpClass()
test.setUp()
test.build_reputation("est2@test.com", 5, "LEGITIMATE")
mock = test.create_mock("est2@test.com", "Hello world")
res = test.run_pipeline(mock)
print("NEGATIVE EVIDENCE:")
print(res["raw_analysis"]["ai_orchestrator"]["negative_evidence"])
