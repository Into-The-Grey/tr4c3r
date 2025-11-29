.PHONY: install test lint format clean

install:
	pipenv install --dev

test:
	pipenv run pytest

lint:
	pipenv run black --check .
	pipenv run isort --check-only .
	pipenv run flake8

format:
	pipenv run black .
	pipenv run isort .

clean:
	find . -type d -name '__pycache__' -exec rm -rf {} +
	find . -type d -name '.pytest_cache' -exec rm -rf {} +
	find . -type d -name '.mypy_cache' -exec rm -rf {} +
	rm -rf dist/ build/ *.egg-info
