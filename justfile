# Default command
default:
    @just --list

# Install dependencies
install:
    python3 -m venv venv
    source venv/bin/activate && pip install -r requirements.txt

# Run test
test domain:
    source venv/bin/activate && python3 test.py {{domain}}

# Show help information
help:
    @echo "Available commands:"
    @echo "  just install    - Install dependencies"
    @echo "  just test <domain> - Run test"
    @echo "  just help       - Show help information" 