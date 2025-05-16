# YARA to MITRE Mapping Toolkit

This toolkit contains a set of Python scripts used to map YARA rules to the [MITRE ATT&CK](https://attack.mitre.org/) framework using heuristic methods. The script helps in identifying corresponding tactics, techniques, and subtechniques from MITRE ATT&CK for YARA rules, providing insights into possible attack scenarios.

## Scripts

### `yaraToMitre.py`

This is the **main script**. It performs the following tasks:
- Downloads MITRE ATT&CK tactics, techniques, and subtechniques from MITRE's official repository.
- Parses YARA rule files from a specified directory.
- Uses heuristic methods (based on regular expressions) to map YARA rules to relevant MITRE ATT&CK tactics and techniques.
- Outputs the results in CSV and JSON formats, including a log of unmatched rules.

**Key Features**:
- Supports mapping for a wide range of MITRE ATT&CK tactics and techniques.
- Generates both a CSV and a JSON output for the rule-to-attack mappings.
- Logs unmatched YARA rules and file names containing those rules.
- Supports advanced MITRE ATT&CK mappings with subtechniques and tactics identification.


## Requirements

- Python 3.6 or higher
- The following Python packages:
  - `mitreattack-python`: MITRE ATT&CK Python library.
  - `pandas`: Data manipulation library.
  - `requests`: HTTP library to fetch data from MITRE's repository.
  - `re`: Regular expression library used for pattern matching.
  
  To install the required packages, run:

  ```bash
  pip install mitreattack-python pandas requests
- Yara rules in yara-rules directory