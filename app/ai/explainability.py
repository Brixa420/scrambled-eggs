""
Advanced Explanation Mechanisms for AI Decisions

This module provides sophisticated explanation techniques for the AI decision framework,
including SHAP values, LIME, and attention visualization.
"""

import numpy as np
import torch
import shap
import lime
import lime.lime_tabular
from typing import Dict, List, Any, Tuple
from matplotlib import pyplot as plt
import seaborn as sns

class AIExplainer:
    """Advanced explanation generator for AI decisions."""
    
    def __init__(self, model: torch.nn.Module, feature_names: List[str], class_names: List[str]):
        """
        Initialize the explainer.
        
        Args:
            model: The trained PyTorch model
            feature_names: List of feature names for interpretation
            class_names: List of class names for interpretation
        """
        self.model = model
        self.feature_names = feature_names
        self.class_names = class_names
        self.device = next(model.parameters()).device
        
        # Initialize SHAP explainer
        self.shap_explainer = None
        self._init_shap()
        
        # Initialize LIME explainer
        self.lime_explainer = lime.lime_tabular.LimeTabularExplainer(
            training_data=np.zeros((1, len(feature_names))),  # Dummy data, will be updated
            feature_names=feature_names,
            class_names=class_names,
            mode="classification"
        )
    
    def _init_shap(self, background_data: np.ndarray = None):
        """Initialize the SHAP explainer with background data."""
        if background_data is None:
            # Use mean values as background if no data provided
            background_data = np.zeros((1, len(self.feature_names)))
        
        # Define model wrapper for SHAP
        def model_predict(x):
            with torch.no_grad():
                tensor_x = torch.FloatTensor(x).to(self.device)
                outputs = self.model(tensor_x)
                return outputs.cpu().numpy()
        
        self.shap_explainer = shap.KernelExplainer(
            model_predict,
            background_data,
            link="logit"
        )
    
    def explain_with_shap(self, input_data: np.ndarray, nsamples: int = 100) -> Dict[str, Any]:
        """
        Generate SHAP values for the input.
        
        Args:
            input_data: Input data to explain (batch_size x num_features)
            nsamples: Number of samples to use for SHAP value estimation
            
        Returns:
            Dictionary containing SHAP values and visualization data
        """
        if self.shap_explainer is None:
            self._init_shap()
        
        # Calculate SHAP values
        shap_values = self.shap_explainer.shap_values(
            input_data,
            nsamples=nsamples,
            l1_reg="num_features(10)"
        )
        
        # Process SHAP values for each class
        explanations = {}
        for i, class_name in enumerate(self.class_names):
            class_shap = shap_values[i] if isinstance(shap_values, list) else shap_values
            
            # Get top contributing features
            avg_shap = np.mean(np.abs(class_shap), axis=0)
            top_feature_indices = np.argsort(avg_shap)[::-1][:5]  # Top 5 features
            
            explanations[class_name] = {
                'shap_values': class_shap,
                'top_features': [self.feature_names[idx] for idx in top_feature_indices],
                'top_contributions': [float(avg_shap[idx]) for idx in top_feature_indices]
            }
        
        return {
            'shap_values': shap_values,
            'feature_importances': self._get_feature_importance(shap_values),
            'explanations': explanations,
            'visualization': self._create_shap_plot(input_data, shap_values)
        }
    
    def explain_with_lime(self, input_data: np.ndarray, num_features: int = 5) -> Dict[str, Any]:
        """
        Generate LIME explanations for the input.
        
        Args:
            input_data: Input data to explain (single sample)
            num_features: Number of features to include in the explanation
            
        Returns:
            Dictionary containing LIME explanation
        """
        if len(input_data.shape) == 1:
            input_data = input_data.reshape(1, -1)
        
        # Define prediction function for LIME
        def predict_proba(x):
            with torch.no_grad():
                tensor_x = torch.FloatTensor(x).to(self.device)
                outputs = self.model(tensor_x)
                return torch.softmax(outputs, dim=1).cpu().numpy()
        
        # Generate explanation
        explanation = self.lime_explainer.explain_instance(
            input_data[0],
            predict_proba,
            num_features=num_features,
            top_labels=len(self.class_names)
        )
        
        # Process explanation
        lime_data = []
        for label in range(len(self.class_names)):
            exp = explanation.local_exp.get(label, [])
            lime_data.append({
                'class': self.class_names[label],
                'features': [self.feature_names[f[0]] for f in exp],
                'weights': [float(f[1]) for f in exp],
                'intercept': float(explanation.intercept[label])
            })
        
        return {
            'explanation': lime_data,
            'visualization': self._create_lime_plot(explanation, input_data)
        }
    
    def _get_feature_importance(self, shap_values: np.ndarray) -> Dict[str, float]:
        """Calculate feature importance from SHAP values."""
        if isinstance(shap_values, list):
            # For multi-class, average across classes
            shap_values = np.mean(np.abs(shap_values), axis=0)
        
        # Calculate mean absolute SHAP values
        mean_shap = np.mean(np.abs(shap_values), axis=0)
        
        # Normalize to sum to 1
        total = np.sum(mean_shap)
        if total > 0:
            mean_shap = mean_shap / total
        
        return {feature: float(importance) 
                for feature, importance in zip(self.feature_names, mean_shap)}
    
    def _create_shap_plot(self, input_data: np.ndarray, shap_values: np.ndarray) -> plt.Figure:
        """Create a SHAP summary plot."""
        plt.figure(figsize=(10, 6))
        
        if isinstance(shap_values, list):
            # For multi-class, create a bar plot of mean absolute SHAP values
            mean_shap = np.mean([np.abs(sv) for sv in shap_values], axis=(0, 1))
            top_indices = np.argsort(mean_shap)[-10:][::-1]  # Top 10 features
            
            plt.barh(
                [self.feature_names[i] for i in top_indices],
                mean_shap[top_indices]
            )
            plt.title('Feature Importance (SHAP)')
        else:
            # For binary classification, create a beeswarm plot
            shap.summary_plot(
                shap_values,
                input_data,
                feature_names=self.feature_names,
                show=False
            )
            plt.tight_layout()
        
        return plt.gcf()
    
    def _create_lime_plot(self, explanation, input_data: np.ndarray) -> plt.Figure:
        """Create a LIME explanation plot."""
        fig = plt.figure(figsize=(10, 6))
        
        # Get the top class
        with torch.no_grad():
            pred = self.model(torch.FloatTensor(input_data).to(self.device))
            pred_class = torch.argmax(pred).item()
        
        # Get explanation for the top class
        exp = explanation.local_exp.get(pred_class, [])
        
        if not exp:
            return fig
        
        # Create horizontal bar plot
        features = [self.feature_names[f[0]] for f in exp]
        weights = [f[1] for f in exp]
        
        colors = ['green' if w > 0 else 'red' for w in weights]
        y_pos = np.arange(len(features))
        
        plt.barh(y_pos, weights, color=colors, alpha=0.6)
        plt.yticks(y_pos, features)
        plt.xlabel('Weight')
        plt.title(f'LIME Explanation for {self.class_names[pred_class]}')
        plt.tight_layout()
        
        return fig
    
    def generate_counterfactual(self, input_data: np.ndarray, target_class: int, 
                             learning_rate: float = 0.01, max_iter: int = 1000) -> Tuple[np.ndarray, Dict]:
        """
        Generate a counterfactual explanation by finding the minimal changes needed
        to change the model's prediction to the target class.
        
        Args:
            input_data: Original input data
            target_class: Desired target class
            learning_rate: Learning rate for optimization
            max_iter: Maximum number of iterations
            
        Returns:
            Tuple of (counterfactual, explanation)
        """
        input_tensor = torch.FloatTensor(input_data).to(self.device).requires_grad_(True)
        target = torch.LongTensor([target_class]).to(self.device)
        
        optimizer = torch.optim.Adam([input_tensor], lr=learning_rate)
        
        for i in range(max_iter):
            self.model.zero_grad()
            output = self.model(input_tensor.unsqueeze(0))
            
            # Calculate loss (cross-entropy + L1 regularization for sparsity)
            loss = torch.nn.functional.cross_entropy(output, target)
            l1_reg = 0.001 * torch.norm(input_tensor - torch.FloatTensor(input_data).to(self.device), 1)
            total_loss = loss + l1_reg
            
            # Optimize
            total_loss.backward()
            optimizer.step()
            
            # Project back to valid input space if needed
            with torch.no_grad():
                input_tensor.data = torch.clamp(input_tensor, 0, 1)  # Assuming input is normalized [0,1]
            
            # Early stopping if we've reached the target class
            if torch.argmax(output) == target:
                break
        
        # Calculate feature changes
        original_pred = torch.softmax(
            self.model(torch.FloatTensor(input_data).unsqueeze(0).to(self.device)), 
            dim=1
        )
        counterfactual_pred = torch.softmax(
            self.model(input_tensor.unsqueeze(0)), 
            dim=1
        )
        
        # Create explanation
        explanation = {
            'original_class': int(torch.argmax(original_pred).item()),
            'target_class': target_class,
            'original_confidence': float(original_pred[0, torch.argmax(original_pred)]),
            'counterfactual_confidence': float(counterfactual_pred[0, target_class]),
            'feature_changes': {},
            'success': torch.argmax(counterfactual_pred).item() == target_class
        }
        
        # Calculate and sort feature changes
        changes = (input_tensor.cpu().detach().numpy() - input_data).flatten()
        changed_indices = np.argsort(np.abs(changes))[::-1]  # Sort by magnitude of change
        
        for idx in changed_indices[:5]:  # Top 5 most changed features
            if abs(changes[idx]) > 1e-3:  # Only include meaningful changes
                explanation['feature_changes'][self.feature_names[idx]] = {
                    'original': float(input_data[idx]),
                    'new': float(input_tensor.cpu().detach().numpy()[idx]),
                    'change': float(changes[idx])
                }
        
        return input_tensor.cpu().detach().numpy(), explanation

# Example usage
if __name__ == "__main__":
    # Example model (replace with your actual model)
    class DummyModel(torch.nn.Module):
        def __init__(self, input_size, num_classes):
            super().__init__()
            self.fc = torch.nn.Linear(input_size, num_classes)
        
        def forward(self, x):
            return self.fc(x)
    
    # Initialize model and explainer
    input_size = 10
    num_classes = 3
    model = DummyModel(input_size, num_classes)
    
    feature_names = [f"feature_{i}" for i in range(input_size)]
    class_names = ["class_0", "class_1", "class_2"]
    
    explainer = AIExplainer(model, feature_names, class_names)
    
    # Generate some example data
    np.random.seed(42)
    X_test = np.random.rand(5, input_size)
    
    # Get SHAP explanations
    for i in range(3):
        print(f"\nSHAP Explanation for sample {i+1}:")
        shap_exp = explainer.explain_with_shap(X_test[i:i+1])
        print(f"Feature importances: {shap_exp['feature_importances']}")
    
    # Get LIME explanation for the first sample
    lime_exp = explainer.explain_with_lime(X_test[0])
    print("\nLIME Explanation:", lime_exp)
    
    # Generate a counterfactual explanation
    print("\nGenerating counterfactual...")
    cf, cf_exp = explainer.generate_counterfactual(
        X_test[0], 
        target_class=1,  # Try to change to class 1
        learning_rate=0.1,
        max_iter=1000
    )
    print(f"Counterfactual explanation: {cf_exp}")
