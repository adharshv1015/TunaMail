import json
import os
from .tokenizer import SecurityTokenizer
from .vocabulary import Vocabulary
from .features import FeatureExtractor

LABELS = ["LEGITIMATE", "LIKELY_LEGITIMATE", "SUSPICIOUS", "PHISHING", "UNKNOWN"]

class DatasetLoader:
    def __init__(self, vocab: Vocabulary = None):
        self.tokenizer = SecurityTokenizer()
        self.vocab = vocab or Vocabulary()
        self.feature_extractor = FeatureExtractor()
        
    def load(self, filepath: str, is_training: bool = False):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Dataset not found: {filepath}")
            
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        X_tokens = []
        X_features = []
        Y = []
        
        for item in data:
            email_data = item.get("email", {})
            analysis_data = item.get("analysis", {})
            label_str = item.get("label", "UNKNOWN")
            
            # Text processing
            text = f"{email_data.get('subject', '')} {email_data.get('body', '')}"
            tokens = self.tokenizer.tokenize(text)
            
            if is_training:
                for token in tokens:
                    self.vocab.add_token(token)
                    
            token_ids = self.vocab.encode(tokens)
            
            # Feature extraction
            feat_dict = self.feature_extractor.extract(email_data, analysis_data)
            feat_vector = self.feature_extractor.vector_format(feat_dict)
            
            X_tokens.append(token_ids)
            X_features.append(feat_vector)
            
            # Label
            label_id = LABELS.index(label_str) if label_str in LABELS else 4
            Y.append(label_id)
            
        return X_tokens, X_features, Y
