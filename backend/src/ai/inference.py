import os
from .tokenizer import SecurityTokenizer
from .vocabulary import Vocabulary
from .features import FeatureExtractor
from .model import LocalSecurityModel
from .reasoning import AIReasoningEngine
from .dataset import DatasetLoader

AI_DIR = os.path.dirname(os.path.abspath(__file__))
VOCAB_PATH = os.path.join(AI_DIR, "models", "vocab.json")
MODEL_PATH = os.path.join(AI_DIR, "models", "mlp_model.pkl")
DEV_DATASET_PATH = os.path.join(AI_DIR, "data", "dev_dataset.json")

class TunaMailAIEngine:
    def __init__(self):
        self.tokenizer = SecurityTokenizer()
        self.vocab = Vocabulary(VOCAB_PATH)
        self.feature_extractor = FeatureExtractor()
        self.model = LocalSecurityModel(MODEL_PATH)
        self.reasoning = AIReasoningEngine()
        
        self.vocab_size = 1000  # Fixed simple vocab size limit for BoW vector
        
        # Bootstrap model if not trained (so it doesn't fail on first run)
        if not self.model.is_trained:
            self._bootstrap_dev_model()

    def _bootstrap_dev_model(self):
        """
        Trains the local model on the dev dataset if no saved model is found.
        """
        try:
            loader = DatasetLoader(self.vocab)
            X_tokens, X_features, Y = loader.load(DEV_DATASET_PATH, is_training=True)
            self.vocab.save(VOCAB_PATH)
            self.model.train(X_tokens, X_features, Y, self.vocab_size)
            self.model.save(MODEL_PATH)
        except Exception as e:
            print(f"Warning: AI Model failed to bootstrap: {e}")

    def analyze_email(self, parsed_email: dict, analysis: dict = None) -> dict:
        """
        Main entry point for local AI/ML email analysis.
        """
        if not analysis:
            analysis = {}
            
        # 1. Feature Extraction
        feat_dict = self.feature_extractor.extract(parsed_email, analysis)
        feat_vector = self.feature_extractor.vector_format(feat_dict)
        
        # 2. Tokenization
        text = f"{parsed_email.get('subject', '')} {parsed_email.get('body', '')}"
        tokens = self.tokenizer.tokenize(text)
        token_ids = self.vocab.encode(tokens)
        
        # 3. Model Prediction
        predicted_class, probabilities = self.model.predict(token_ids, feat_vector, self.vocab_size)
        
        # 4. Reasoning Engine
        reasoning_result = self.reasoning.evaluate(predicted_class, probabilities, feat_dict)
        
        return {
            "model_version": "local-mlp-v1",
            "predicted_class": reasoning_result["predicted_class"],
            "probabilities": probabilities,
            "link_only": bool(feat_dict.get("link_only", False)),
            "limited_context": bool(feat_dict.get("limited_context", False)),
            "reasoning_state": reasoning_result["reasoning_state"],
            "confidence": reasoning_result["confidence"],
            "evidence": reasoning_result["evidence"],
            "features": feat_dict
        }

# Global singleton for inference to keep model in memory
_ai_engine = None

def get_ai_engine():
    global _ai_engine
    if _ai_engine is None:
        _ai_engine = TunaMailAIEngine()
    return _ai_engine

def analyze_email(parsed_email: dict, analysis: dict = None):
    engine = get_ai_engine()
    return engine.analyze_email(parsed_email, analysis)
