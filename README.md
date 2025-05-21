# YARA to MITRE Mapping Toolkit

This toolkit contains a set of Python scripts used to map YARA rules to the [MITRE ATT&CK](https://attack.mitre.org/) framework using heuristic methods. The script helps in identifying corresponding tactics, techniques, and subtechniques from MITRE ATT&CK for YARA rules, providing insights into possible attack scenarios.

---

## **Scripts Overview**

### `analyzeYaraRules.py`

Before running the **`yaraToMitre.py`** script, **`analyzeYaraRules.py`** must first be executed. This script performs the initial analysis on YARA rules to prepare the necessary data, ensuring that the subsequent mapping process can occur correctly.

- **Purpose**: Analyzes YARA rule files in the specified directory.
- **Outcome**: Outputs a processed list of YARA rules with necessary metadata for the mapping step.

### `yaraToMitre.py`

Once **`analyzeYaraRules.py`** has completed, run the **`yaraToMitre.py`** script to map the analyzed YARA rules to MITRE ATT&CK tactics, techniques, and subtechniques.

- **Purpose**: Maps YARA rules to MITRE ATT&CK using heuristic methods and outputs the results in CSV and JSON formats.
- **Outcome**: Generates a report on which MITRE techniques and tactics correspond to the YARA rules, along with unmatched rules.

**Key Features**:
- Supports mapping for a wide range of MITRE ATT&CK tactics and techniques.
- Generates both a CSV and a JSON output for the rule-to-attack mappings.
- Logs unmatched YARA rules and file names containing those rules.
- Supports advanced MITRE ATT&CK mappings with subtechniques and tactics identification.

---

## **Required Workflow**

1. **Run `analyzeYaraRules.py`** to analyze the YARA rules and prepare the data.

```bash
python analyzeYaraRules.py -D /path/to/yara-rules
```

2. **Run `yaraToMitre.py`** to map the analyzed YARA rules to the MITRE ATT&CK framework.

```bash
python yaraToMitre.py -D /path/to/yara-rules
```

---

## **Requirements**

- Python 3.6 or higher
- The following Python packages:
  - `mitreattack-python`: MITRE ATT&CK Python library.
  - `pandas`: Data manipulation library.
  - `requests`: HTTP library to fetch data from MITRE's repository.
  - `re`: Regular expression library used for pattern matching.

To install the required packages, run:

```bash
pip install mitreattack-python pandas requests
```

---

## **License and Attribution**

This toolkit is distributed under the GPL-3.0 license.

Portions of the scoring methodology or heuristic strategies referenced in this toolkit are adapted from the [YARA Style Guide by Neo23x0](https://github.com/Neo23x0/YARA-Style-Guide), licensed under [GNU General Public License v3.0 (GPL-3.0)](https://www.gnu.org/licenses/gpl-3.0.html).

