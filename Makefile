.PHONY: requirements
requirements:
	python3 -m pip install -r requirements/development.txt

.PHONY: check
check:
	ruff format --check .
	ruff check .

.PHONY: format
format:
	ruff format .

.PHONY: coverage
coverage:
	coverage run -m unittest -v
	coverage report --show-missing

.PHONY: test
test:
	python -m unittest -v ${tests}
