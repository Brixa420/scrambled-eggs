# P2P Manager Tests

This directory contains tests for the P2P Manager component of the Scrambled Eggs application.

## Test Structure

- **Unit Tests**: Test individual components in isolation
  - Message signing/verification
  - Encryption/decryption
  - Peer management
  - Rate limiting
  - Blacklisting

- **Integration Tests**: Test interactions between components
  - Peer connection establishment
  - Message exchange
  - Error handling
  - Reconnection logic

- **Load Tests**: Test performance and scalability
  - Multiple peer connections
  - High message throughput
  - Resource usage

## Running Tests

### Prerequisites

1. Install the required test dependencies:
   ```bash
   pip install -r requirements-test.txt
   ```

### Running All Tests

```bash
pytest -v
```

### Running Specific Test Types

Run only unit tests:
```bash
pytest -v tests/test_p2p_manager.py::TestP2PManagerUnit
```

Run only integration tests:
```bash
pytest -v tests/test_p2p_manager.py::TestP2PManagerIntegration
```

Run load tests (requires more resources):
```bash
pytest -v tests/test_p2p_manager.py::TestP2PManagerLoad -m "load_test"
```

### Running with Coverage

To generate a coverage report:
```bash
pytest --cov=app --cov-report=html
```

## Test Configuration

- Test configuration is managed in `conftest.py`
- Test utilities are in `test_utils.py`
- Mock implementations are provided for external dependencies

## Writing New Tests

1. For unit tests, add methods to the appropriate test class in `test_p2p_manager.py`
2. For new test categories, create a new test class that inherits from `TestP2PManagerBase`
3. Use the provided test utilities and mocks when possible
4. Add appropriate assertions to verify behavior
5. Include docstrings that explain what each test is verifying

## Test Data

- Test data should be generated programmatically in the test setup
- Use unique identifiers to avoid test interference
- Clean up any resources in the teardown method

## Debugging Tests

To debug a failing test:

1. Run the specific test with `-s` to see print output:
   ```bash
   pytest -v tests/test_p2p_manager.py::TestP2PManagerUnit::test_specific_test -s
   ```

2. Use `pdb` for interactive debugging:
   ```python
   import pdb; pdb.set_trace()
   ```

## Performance Testing

Load tests are marked with `@pytest.mark.load_test` and can be run with:
```bash
pytest -v -m "load_test"
```

These tests may take longer to run and may require more system resources.
