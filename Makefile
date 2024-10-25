# Makefile for installing dependencies and running main.py

# Define variables
PYTHON=python3
PIP=pip3
REQUIREMENTS=requirements.txt

# Target to install dependencies
install:
	$(PIP) install -r $(REQUIREMENTS)

# Target to run the main.py file
run: install
	$(PYTHON) main.py

# Clean target to remove __pycache__ and other temporary files
clean:
	find . -type d -name "__pycache__" -exec rm -r {} +
	rm -rf *.pyc

# Phony targets
.PHONY: install run clean
