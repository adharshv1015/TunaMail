import os
import joblib
import numpy as np
from sklearn.neural_network import MLPClassifier
from .dataset import LABELS

class LocalSecurityModel:
    def __init__(self, model_path: str = None):
        self.model_path = model_path
        self.model = None
        self.is_trained = False
        
        if self.model_path and os.path.exists(self.model_path):
            self.load()
            
    def _prepare_inputs(self, X_tokens, X_features, vocab_size):
        """
        Combines token IDs (Bag of Words) with structured features into a single matrix.
        """
        X_combined = []
        for tokens, features in zip(X_tokens, X_features):
            # Create a Bag-of-Words vector
            bow = np.zeros(vocab_size)
            for token_id in tokens:
                if token_id < vocab_size:
                    bow[token_id] += 1
            
            # Combine BoW with structured features
            combined = np.concatenate([bow, features])
            X_combined.append(combined)
            
        return np.array(X_combined)
        
    def train(self, X_tokens, X_features, Y, vocab_size: int):
        X_train = self._prepare_inputs(X_tokens, X_features, vocab_size)
        Y_train = np.array(Y)
        
        # Lightweight architecture suitable for local inference
        self.model = MLPClassifier(
            hidden_layer_sizes=(64, 32),
            activation='relu',
            solver='adam',
            max_iter=500,
            random_state=42
        )
        
        # In case we only have one class in a small dev dataset, we fake it for sklearn
        classes = np.unique(Y_train)
        if len(classes) < len(LABELS):
            # Hack to ensure all classes are known to MLPClassifier even if missing in dev set
            self.model.classes_ = np.arange(len(LABELS))
            # Just do a standard fit
            
        self.model.fit(X_train, Y_train)
        self.is_trained = True
        
        if self.model_path:
            self.save()
            
    def predict(self, token_ids, features, vocab_size: int):
        if not self.is_trained or not self.model:
            # Fallback if model isn't trained (e.g. fresh start without dataset)
            return "UNKNOWN", {label: 0.0 for label in LABELS}
            
        X_input = self._prepare_inputs([token_ids], [features], vocab_size)
        
        try:
            proba = self.model.predict_proba(X_input)[0]
            pred_idx = np.argmax(proba)
            pred_label = LABELS[pred_idx]
            
            probabilities = {
                LABELS[i]: float(proba[i]) for i in range(len(LABELS))
            }
            
            return pred_label, probabilities
        except Exception:
            return "UNKNOWN", {label: 0.0 for label in LABELS}

    def save(self, filepath: str = None):
        path = filepath or self.model_path
        if not path:
            return
            
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        joblib.dump(self.model, path)
        
    def load(self, filepath: str = None):
        path = filepath or self.model_path
        if not path:
            return
            
        self.model = joblib.load(path)
        self.is_trained = True
