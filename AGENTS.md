# AGENTS instructions

These guidelines apply to the entire repository.

## Pull Requests
- Describe the user-visible impact of the change in a short summary.
- Include a "Testing" section listing commands executed and their output.
- Run `python -m py_compile virustotal_lookup/*.py VirusTotalLookup.py` before submitting a PR.

## Coding Style
- Use 4 spaces for indentation.
- Provide type hints for all function parameters and return values.
- Document new modules and functions with docstrings.
- Prefer f-strings for string formatting.
- Keep all application code within the `virustotal_lookup` package.

