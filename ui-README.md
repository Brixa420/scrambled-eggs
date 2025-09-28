# Scrambled Eggs P2P Messenger - UI Components

This directory contains the user interface components for the Scrambled Eggs P2P Messenger application.

## Features

- **Security Dashboard**: Monitor security status and events
- **Contact Management**: Add, remove, and manage contacts
- **Message Status Indicators**: See message delivery status in real-time
- **File Transfer**: Securely send and receive files
- **Group Chat**: Create and manage group conversations

## Prerequisites

- Python 3.8 or higher
- Jupyter Notebook or JupyterLab
- Required Python packages (install using `pip install -r requirements-ui.txt`)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/scrambled-eggs.git
   cd scrambled-eggs
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements-ui.txt
   ```

## Running the Application

### Option 1: Run in Jupyter Notebook/Lab

1. Start Jupyter Notebook or JupyterLab:
   ```bash
   jupyter notebook
   # or
   jupyter lab
   ```

2. Open `notebooks/demo.ipynb` and run the cells to start the application.

### Option 2: Run as a Standalone Application

1. Run the main application:
   ```bash
   python -m app
   ```

   Use the following command-line arguments:
   - `--gui`: Launch the graphical user interface (default)
   - `--cli`: Launch the command line interface

## UI Components

### Security Dashboard

Monitor the security status of your P2P connections, view recent security events, and adjust security settings.

### Contact Manager

- View your contacts
- Add new contacts
- Manage contact information
- See contact online status

### Message Status

- Real-time message delivery status
- Read receipts
- Message encryption indicators

### File Transfer

- Send and receive files securely
- Track transfer progress
- View transfer history

### Group Chat

- Create and join group chats
- Send messages to multiple participants
- Manage group members

## Development

### Code Style

We use the following tools to maintain code quality:

- **Black** for code formatting
- **isort** for import sorting
- **flake8** for linting
- **mypy** for static type checking

Run the following commands to ensure your code follows our style guidelines:

```bash
black .
isort .
flake8
mypy .
```

### Testing

Run the test suite with:

```bash
pytest
```

For test coverage:

```bash
pytest --cov=app tests/
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to all contributors who have helped with this project
- Built with ❤️ and open source
