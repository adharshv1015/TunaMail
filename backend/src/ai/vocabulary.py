import json
import os

SPECIAL_TOKENS = ["<PAD>", "<UNK>", "<URL>", "<EMAIL>", "<DOMAIN>", "<NUMBER>"]

class Vocabulary:
    def __init__(self, vocab_file: str = None):
        self.token_to_id = {}
        self.id_to_token = {}
        self.vocab_file = vocab_file
        
        # Initialize special tokens
        for idx, token in enumerate(SPECIAL_TOKENS):
            self.token_to_id[token] = idx
            self.id_to_token[idx] = token
            
        self.unk_id = self.token_to_id["<UNK>"]
        
        if self.vocab_file and os.path.exists(self.vocab_file):
            self.load()

    def add_token(self, token: str):
        if token not in self.token_to_id:
            idx = len(self.token_to_id)
            self.token_to_id[token] = idx
            self.id_to_token[idx] = token
        return self.token_to_id[token]

    def get_id(self, token: str):
        return self.token_to_id.get(token, self.unk_id)

    def get_token(self, idx: int):
        return self.id_to_token.get(idx, "<UNK>")

    def encode(self, tokens: list):
        return [self.get_id(t) for t in tokens]

    def save(self, filepath: str = None):
        path = filepath or self.vocab_file
        if not path:
            raise ValueError("Vocabulary file path not provided.")
            
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.token_to_id, f, ensure_ascii=False, indent=2)

    def load(self, filepath: str = None):
        path = filepath or self.vocab_file
        if not path:
            raise ValueError("Vocabulary file path not provided.")
            
        with open(path, 'r', encoding='utf-8') as f:
            self.token_to_id = json.load(f)
            
        self.id_to_token = {int(v): k for k, v in self.token_to_id.items()}
        self.unk_id = self.token_to_id.get("<UNK>", 1)
        
    def __len__(self):
        return len(self.token_to_id)
