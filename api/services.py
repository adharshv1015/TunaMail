from src.analyzer import EmailAnalyzer


class AnalysisService:

    def __init__(self):
        self.analyzer = EmailAnalyzer()


    def analyze_email(self, file_path):

        result = self.analyzer.analyze(
            file_path
        )

        return result


analysis_service = AnalysisService()
