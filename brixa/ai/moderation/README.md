# Brixa AI Content Moderation System

A modular, extensible content moderation system for text, images, and video content. This system provides AI-powered content filtering and moderation capabilities for the Brixa platform.

## Features

- **Multi-modal Moderation**: Supports text, image, and video content
- **Extensible Architecture**: Easily add new moderation models and rules
- **Asynchronous Processing**: Built with asyncio for high performance
- **Configurable Policies**: Define custom moderation rules and thresholds
- **Detailed Reporting**: Provides comprehensive violation reports
- **Multiple AI Backends**: Supports various AI models (HuggingFace, Google Vision, etc.)

## Installation

```bash
# Install the required dependencies
pip install -r requirements.txt

# Additional system dependencies (Ubuntu/Debian)
sudo apt-get install libmagic-dev
```

## Usage

### Basic Usage

```python
from brixa.ai.moderation import get_moderator
from brixa.ai.moderation.base import ContentType
import asyncio

async def moderate_content():
    # Get a text moderator
    text_moderator = get_moderator(ContentType.TEXT)
    
    # Moderate some text
    result = await text_moderator.moderate("This is some text to moderate")
    print(f"Action: {result.action}, Confidence: {result.confidence}")
    
    # Get an image moderator
    image_moderator = get_moderator(ContentType.IMAGE)
    
    # Moderate an image (from file path or bytes)
    with open("example.jpg", "rb") as f:
        image_data = f.read()
    
    result = await image_moderator.moderate(image_data)
    print(f"Action: {result.action}, Reasons: {result.reasons}")

# Run the async function
asyncio.run(moderate_content())
```

### Advanced Configuration

```yaml
# config.yaml
models:
  huggingface:
    model: facebook/bart-large-mnli
    threshold: 0.8
  google_vision:
    credentials_path: /path/to/credentials.json
    threshold: 0.75

policies:
  hate_speech:
    description: "Block hate speech and offensive content"
    action: "block"
    conditions:
      - model: "huggingface"
        label: "hate"
        threshold: 0.8
  
  explicit_content:
    description: "Flag explicit or adult content"
    action: "flag"
    conditions:
      - model: "google_vision"
        label: "adult"
        threshold: 0.7
```

```python
from brixa.ai.moderation import ModeratorFactory
import yaml

# Load configuration
with open("config.yaml") as f:
    config = yaml.safe_load(f)

# Create a moderator with custom config
moderator = ModeratorFactory.create_moderator("text", config)
```

## Architecture

### Core Components

- **Moderator**: Base class for all content moderators
- **Detectors**: Specialized components for different content types
- **Policies**: Rules that define what constitutes a violation
- **Models**: AI/ML models for content analysis
- **Utils**: Helper functions for content processing

### Content Types

- **Text**: Blog posts, comments, messages, etc.
- **Images**: Photos, illustrations, memes
- **Video**: Video content with frame analysis
- **Audio**: Speech and audio content (future)

## Extending the System

### Adding a New Model

1. Create a new detector class that inherits from `ContentModerator`
2. Implement the required methods (`moderate`, `_setup`, etc.)
3. Register the detector in the `ModeratorFactory`

### Creating Custom Policies

Define policies in YAML or JSON format:

```yaml
custom_policy:
  description: "Block spam and low-quality content"
  action: "block"
  conditions:
    - model: "spam_detector"
      label: "spam"
      threshold: 0.9
    - model: "quality_checker"
      label: "low_quality"
      threshold: 0.8
```

## Performance Considerations

- **Batch Processing**: Process multiple items in parallel when possible
- **Caching**: Cache model predictions for similar content
- **Resource Management**: Release resources when done (especially GPU memory)
- **Rate Limiting**: Respect API rate limits for cloud-based models

## Error Handling

The system provides detailed error information through custom exceptions:

```python
from brixa.ai.moderation.exceptions import (
    ModerationError,
    PolicyViolationError,
    ModelLoadingError,
    ContentProcessingError,
    ConfigurationError
)

try:
    # Moderation code here
    pass
except PolicyViolationError as e:
    print(f"Content violated policies: {e.violations}")
except ContentProcessingError as e:
    print(f"Error processing content: {e}")
```

## Testing

Run the test suite:

```bash
pytest tests/
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.
