"""
Simple sentiment analysis model for demonstration.
"""
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import numpy as np

class SentimentClassifier(nn.Module):
    def __init__(self, vocab_size=10000, embed_dim=64, hidden_dim=64, output_dim=2):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.rnn = nn.LSTM(embed_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, output_dim)
        self.softmax = nn.Softmax(dim=1)
        
    def forward(self, x):
        embedded = self.embedding(x)
        _, (hidden, _) = self.rnn(embedded)
        output = self.fc(hidden.squeeze(0))
        return self.softmax(output)

class SentimentDataset(Dataset):
    def __init__(self, num_samples=1000, seq_length=50):
        self.data = torch.randint(0, 10000, (num_samples, seq_length))
        self.labels = torch.randint(0, 2, (num_samples,))
        
    def __len__(self):
        return len(self.data)
    
    def __getitem__(self, idx):
        return self.data[idx], self.labels[idx]

def train_model(epochs=5):
    model = SentimentClassifier()
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters())
    dataset = SentimentDataset()
    loader = DataLoader(dataset, batch_size=32, shuffle=True)
    
    for epoch in range(epochs):
        for x, y in loader:
            optimizer.zero_grad()
            outputs = model(x)
            loss = criterion(outputs, y)
            loss.backward()
            optimizer.step()
        print(f"Epoch {epoch+1}, Loss: {loss.item():.4f}")
    
    return model

def save_model(model, path="sentiment_model.pt"):
    torch.save({
        'model_state_dict': model.state_dict(),
        'vocab_size': model.embedding.num_embeddings,
        'embed_dim': model.embedding.embedding_dim,
        'hidden_dim': model.rnn.hidden_size,
        'output_dim': model.fc.out_features
    }, path)

def load_model(path="sentiment_model.pt"):
    checkpoint = torch.load(path)
    model = SentimentClassifier(
        vocab_size=checkpoint['vocab_size'],
        embed_dim=checkpoint['embed_dim'],
        hidden_dim=checkpoint['hidden_dim'],
        output_dim=checkpoint['output_dim']
    )
    model.load_state_dict(checkpoint['model_state_dict'])
    return model
