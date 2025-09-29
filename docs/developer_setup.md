# Developer Setup Guide

This guide will help you set up the development environment for the Scrambled Eggs LLM integration.

## Prerequisites

- Python 3.8 or higher
- Git
- Ollama (for local LLM)
- Redis (for rate limiting, optional)

## Environment Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/scrambled-eggs.git
   cd scrambled-eggs
   ```

2. **Create a Virtual Environment**
   ```bash
   # On Windows
   python -m venv venv
   .\venv\Scripts\activate
   
   # On macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # For development dependencies
   ```

4. **Set Up Environment Variables**
   Create a `.env` file in the project root:
   ```env
   # LLM Configuration
   OLLAMA_BASE_URL=http://localhost:11434
   LLM_MODEL=llama3
   LLM_TIMEOUT=30
   LLM_MAX_RETRIES=3
   LLM_RATE_LIMIT=10
   
   # Redis (optional, for distributed rate limiting)
   REDIS_URL=redis://localhost:6379/0
   ```

## Running the Development Server

1. **Start Ollama**
   ```bash
   ollama serve
   ```

2. **Pull the Model**
   ```bash
   ollama pull llama3
   ```

3. **Run the Example**
   ```bash
   python examples/llm_chat_example.py
   ```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/unit/test_llm_service.py

# Run with coverage
pytest --cov=app tests/
```

### Test Structure

```
tests/
├── unit/               # Unit tests
│   ├── __init__.py
│   ├── test_llm_service.py
│   └── test_chat_service.py
├── integration/        # Integration tests
│   ├── __init__.py
│   └── test_chat_routes.py
└── conftest.py         # Test configuration
```

## Code Style

We use `black` for code formatting and `flake8` for linting.

```bash
# Format code
black .

# Check code style
flake8
```

## Development Workflow

1. Create a new branch for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and run tests:
   ```bash
   pytest
   black .
   flake8
   ```

3. Commit your changes with a descriptive message:
   ```bash
   git add .
   git commit -m "Add feature: your feature description"
   ```

4. Push your branch and create a pull request

## Debugging

### Common Issues

1. **Connection Issues**
   - Verify Ollama is running: `curl http://localhost:11434/api/tags`
   - Check firewall settings

2. **Model Loading**
   - Ensure the model is downloaded: `ollama list`
   - Check available disk space

3. **Performance**
   - Monitor system resources
   - Consider using a smaller model for development

### Debug Logging

Enable debug logging by setting the log level:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Documentation

Update documentation when making changes to the API or functionality.

```bash
# Build documentation
cd docs
make html
```

## CI/CD

The project uses GitHub Actions for CI/CD. The workflow includes:
- Running tests
- Code style checking
- Building documentation
- Deploying to staging/production

## Dependencies

### Core Dependencies

- `requests`: HTTP client for API calls
- `python-dotenv`: Environment variable management
- `pydantic`: Data validation
- `fastapi`: Web framework (if API endpoints are needed)
- `websockets`: For WebSocket support

### Development Dependencies

- `pytest`: Testing framework
- `pytest-cov`: Test coverage
- `black`: Code formatter
- `flake8`: Linter
- `mypy`: Static type checking
- `pytest-asyncio`: Async test support

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
