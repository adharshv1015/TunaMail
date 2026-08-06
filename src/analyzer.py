from src.parser.email_parser import EmailParser
from src.reasoning.are import AnalyticalReasoningEngine


class EmailAnalyzer:

    def __init__(self):

        self.parser = EmailParser()
        self.are = AnalyticalReasoningEngine()


    def analyze(self, email_path):

        parsed = self.parser.parse(email_path)

        reasoning = self.are.evaluate(parsed)

        return {
            "parsed_email": parsed,
            "reasoning": reasoning
        }
