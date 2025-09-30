import torch
import torch.nn as nn
from transformers import AutoModel
from typing import Optional, Dict, Any

class AdvancedSentimentModel(nn.Module):
    """Advanced sentiment analysis model with transformer backbone."""
    
    def __init__(
        self,
        model_name: str = "bert-base-uncased",
        num_labels: int = 2,
        dropout: float = 0.1,
        freeze_embeddings: bool = False
    ):
        super().__init__()
        self.bert = AutoModel.from_pretrained(model_name)
        self.dropout = nn.Dropout(dropout)
        self.classifier = nn.Linear(self.bert.config.hidden_size, num_labels)
        
        # Freeze embeddings if needed
        if freeze_embeddings:
            for param in self.bert.embeddings.parameters():
                param.requires_grad = False
    
    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
        labels: Optional[torch.Tensor] = None
    ) -> Dict[str, Any]:
        outputs = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask,
            return_dict=True
        )
        
        pooled_output = outputs.last_hidden_state[:, 0]  # CLS token
        pooled_output = self.dropout(pooled_output)
        logits = self.classifier(pooled_output)
        
        loss = None
        if labels is not None:
            loss_fct = nn.CrossEntropyLoss()
            loss = loss_fct(logits.view(-1, self.classifier.out_features), 
                           labels.view(-1))
        
        return {
            "loss": loss,
            "logits": logits,
            "hidden_states": outputs.hidden_states,
            "attentions": outputs.attentions
        }
