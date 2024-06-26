# Python Excel

## Description
This script retrieves vulnerabilities from Microsoft's latest tuesday patch, then saves them in a json file and an excel file.

## Modules
To work properly, this script requires the following packages:
- python = "^3.9"
- pandas = "2.2.2"
- requests = "2.32.3"
- datetime = "5.5"
- openpyxl = "^3.1.3"

## Install and Use the script
Install Poetry:
```
pip install poetry
```

In the `pymsrc/` directory:
```
poetry install
```

Execute the script:
```
poetry run python .\src\main.py
```

## Options
- --year : Year of the patch tuesday
- --month : Month of the patch tuesday

## Examples

### Example 1
```
poetry run python .\src\main.py
```

### Example 2
Retrieves all vulnerabilities for December 2023
```
poetry run python .\src\main.py --year 2023 --month 12
```
