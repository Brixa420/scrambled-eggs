# Model Registry

The Model Registry is a core component of the Brixa AI system that provides versioning, tracking, and management of machine learning models. It enables teams to:

- Track model versions and their metadata
- Manage model lifecycle (staging, production, archived)
- Deploy models to serving environments
- Evaluate and compare model performance
- Track model lineage and dependencies
- Serialize and deserialize models across different frameworks

## Core Components

### 1. Model Versioning
- Semantic versioning for models (MAJOR.MINOR.PATCH)
- Support for pre-release versions and build metadata
- Version comparison and constraint resolution

### 2. Model Serialization
- **Framework Support**:
  - PyTorch (including HuggingFace Transformers)
  - TensorFlow/Keras (including HuggingFace)
  - scikit-learn (using joblib)
  - Generic Python objects (using pickle as fallback)
- **Automatic Framework Detection**: Based on model metadata
- **Device Management**: Automatic GPU/CPU handling for PyTorch
- **Security**: Warnings for insecure serialization methods

### 3. Model Metadata
- Comprehensive metadata storage for models
- Support for custom metadata fields
- Model input/output schema definitions
- Performance metrics and evaluation results

### 3. Model Deployment
- Deploy models as REST/gRPC services
- Manage deployment configurations
- Scale deployments up/down
- Monitor deployment status and health

### 4. Model Evaluation
- Track model performance metrics
- Compare model versions
- Generate evaluation reports
- Monitor model drift and performance degradation

## Installation

```bash
# Core dependencies
pip install torch>=1.9.0 tensorflow>=2.6.0 scikit-learn>=1.0.0

# For HuggingFace models
pip install transformers>=4.9.0

# For joblib serialization
pip install joblib>=1.0.0
```

## Usage Examples

### Registering and Saving a Model

```python
from brixa.ai.registry import ModelRegistry, ModelVersion
from brixa.storage.local import LocalStorageNode
import torch
import torch.nn as nn

# Initialize storage and registry
storage = LocalStorageNode("./model_storage")
registry = ModelRegistry(storage)

# Create a simple PyTorch model
class SimpleModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.linear = nn.Linear(10, 2)
    def forward(self, x):
        return self.linear(x)

model = SimpleModel()

# Register a new model version
metadata = registry.register_model(
    name="sentiment-analysis",
    model_type="text-classification",
    framework="pytorch",
    description="A simple sentiment analysis model"
)

# Save the model
registry.save_model(metadata.name, metadata.version, model)
```

### Loading a Model

```python
# Load the model back
loaded_model = registry.load_model("sentiment-analysis")

# For PyTorch models, you can pass device information
device = "cuda" if torch.cuda.is_available() else "cpu"
loaded_model = registry.load_model("sentiment-analysis", device=device)
```

### Working with Different Frameworks

#### TensorFlow/Keras
```python
import tensorflow as tf

# Create a simple Keras model
model = tf.keras.Sequential([
    tf.keras.layers.Dense(10, activation='relu'),
    tf.keras.layers.Dense(2, activation='softmax')
])

# Register and save
metadata = registry.register_model(
    name="image-classifier",
    model_type="image-classification",
    framework="tensorflow"
)
registry.save_model(metadata.name, metadata.version, model)
```

#### scikit-learn
```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import make_classification

# Create and train a simple model
X, y = make_classification(n_samples=100, n_features=4, n_classes=2)
model = RandomForestClassifier().fit(X, y)

# Register and save
metadata = registry.register_model(
    name="random-forest",
    model_type="classification",
    framework="sklearn"
)
registry.save_model(metadata.name, metadata.version, model)
```

### HuggingFace Transformers

```python
from transformers import AutoModelForSequenceClassification

# Load a pretrained model
model = AutoModelForSequenceClassification.from_pretrained("distilbert-base-uncased")

# Register and save
metadata = registry.register_model(
    name="distilbert-sentiment",
    model_type="text-classification",
    framework="pytorch",
    description="DistilBERT for sentiment analysis"
)
registry.save_model(metadata.name, metadata.version, model)
```
    model_type="text-classification",
    framework="pytorch",
    description="Sentiment analysis model for product reviews",
    tags=["nlp", "sentiment-analysis"],
    hyperparameters={
        "learning_rate": 1e-5,
        "batch_size": 32,
        "epochs": 10
    },
    input_schema={
        "type": "object",
        "properties": {
            "text": {"type": "string"}
        },
        "required": ["text"]
    },
    output_schema={
        "type": "object",
        "properties": {
            "sentiment": {"type": "string", "enum": ["positive", "neutral", "negative"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1}
        }
    }
)

print(f"Registered model: {metadata.name} v{metadata.version}")
```

### Deploying a Model

```python
from brixa.ai.registry import ModelDeployer

# Initialize deployer
deployer = ModelDeployer(registry, storage)

# Deploy a model
success, message = deployer.deploy(
    model_name="sentiment-analysis",
    version="1.0.0",
    name="sentiment-analysis-prod",
    replicas=2,
    resources={
        "cpu": "1",
        "memory": "2Gi",
        "gpu": 1
    },
    env_vars={
        "LOG_LEVEL": "INFO",
        "MAX_BATCH_SIZE": "32"
    },
    autoscaling={
        "min_replicas": 1,
        "max_replicas": 5,
        "target_cpu_utilization": 70
    }
)

if success:
    print(f"Deployment started: {message}")
    print(f"Endpoint: {deployer.get_endpoint('sentiment-analysis-prod')}")
else:
    print(f"Deployment failed: {message}")
```

### Evaluating a Model

```python
from brixa.ai.registry import ModelEvaluator

# Initialize evaluator
evaluator = ModelEvaluator(registry)

# Evaluate a model
result = evaluator.evaluate(
    model_name="sentiment-analysis",
    version="1.0.0",
    dataset=test_dataset,
    metrics=["accuracy", "precision", "recall", "f1"]
)

print(f"Evaluation results for {result.model_name} v{result.version}:")
for metric, value in result.metrics.items():
    print(f"  {metric}: {value:.4f}")

# Generate a report
report = evaluator.generate_report(
    model_name="sentiment-analysis",
    version="1.0.0",
    output_format="markdown"
)
print("\nEvaluation Report:")
print(report)
```

## Storage Structure

The Model Registry stores data in the following structure:

```
models/
  ├── _meta/
  │   └── _registry.json          # Registry index
  │
  ├── {model_name}/
  │   ├── {version}_meta.json     # Model metadata
  │   └── {version}/              # Model artifacts
  │       ├── model.pt
  │       ├── config.json
  │       └── ...
  │
  └── deployments/
      └── {deployment_name}/
          ├── config.json         # Deployment configuration
          └── status.json         # Deployment status
```

## Integration

The Model Registry can be integrated with:

- **Training Pipelines**: Automatically register new model versions after training
- **CI/CD Pipelines**: Deploy models to staging/production environments
- **Monitoring Systems**: Track model performance and trigger retraining
- **Feature Stores**: Link models to the features they use

## Configuration

Configuration is done through environment variables:

```bash
# Storage configuration
BRXA_STORAGE_TYPE=local  # or 's3', 'gcs', 'azure'
BRXA_STORAGE_PATH=./data

# Model registry settings
BRXA_MODEL_REGISTRY_PATH=models
BRXA_DEPLOYMENTS_PATH=deployments

# Deployment settings
BRXA_DEFAULT_REPLICAS=1
BRXA_DEFAULT_CPU=1
BRXA_DEFAULT_MEMORY=2Gi
```

## Development

### Running Tests

```bash
pytest tests/ai/registry/
```

### Code Style

This project uses `black` for code formatting and `flake8` for linting.

```bash
black brixa/ai/registry/
flake8 brixa/ai/registry/
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
