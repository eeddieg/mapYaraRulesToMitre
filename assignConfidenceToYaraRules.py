import argparse
import json
import os
import re
import shutil
import sys

# Color palette
class Colors:
  reset = '\033[0m'
  blue = "\033[34m"
  blueBold = "\033[1;34m"
  redBold = '\033[1;31m'
  green = '\033[0;32m'
  greenBold = '\033[1;32m'
  yellow = '\033[0;33m'
  yellowBold = '\033[1;33m'
  red = "\033[31m"
  redBold = "\033[1;31m"

yaraRuleTemplate = [
  {
    "ruleName": "example_rule_full",
    "isPrivate": False,
    "tags": ["malware", "trojan"],

    "meta": {
      "author": "your_name",
      "description": "Detects something interesting",
      "reference": "https://example.com",
      "date": "2025-01-01",
      "version": "1.0",
      "malwareFamily": "ExampleFamily",
      "tlp": "white",
      "hash": "d41d8cd98f00b204e9800998ecf8427e"
    },

    "strings": {
      "$str1": {
        "value": "This program cannot be run in DOS mode",
        "modifiers": ["ascii", "nocase", "fullword"]
      },
      "$str2": {
        "value": "6A 40 68 ?? ?? ?? ?? 6A 00",
        "type": "hex"
      },
      "$str3": {
        "value": "/Trojan\\.[A-Z]+/",
        "type": "regex",
        "modifiers": ["wide", "ascii"]
      },
      "$str4": {
        "value": "ThisIsXOR",
        "modifiers": ["xor"]
      }
    },

    "condition": "any of them",

    "imports": [
      "pe",
      "math",
      "hash",
      "dotnet",
      "cuckoo",
      "magic"
    ],

    "externalVariables": [
      "filename",
      "filepath",
      "extension",
      "filesize"
    ]
  }
]

def reset(folder):
  print(f"{Colors.yellow}Clearing files and folders...{Colors.reset}")
  try:
    if os.path.isdir(folder):
      shutil.rmtree(folder)
  except:
    print(f"Folder {Colors.blue}{folder}{Colors.reset} not deleted!")
  os.system("clear")

def ensureDirectoryExists(path):
  if not os.path.isdir(path):
    print(f"Error: Directory {Colors.blue}{path}{Colors.reset} not found!")
    sys.exit(1)

def readYaraFiles(directory):
  ruleList = {}

  for root, _, files in os.walk(directory):
    for file in files:
      filePath = os.path.join(root, file)
      category = os.path.splitext(filePath)[0]

      with open(filePath, "r", encoding="utf-8") as f:
        content = f.read()

        # ruleMatches = re.findall(r"rule\s+.*?\{.*?\}", content, re.DOTALL)
        ruleMatches = re.findall(r"rule\s+.*?\{.*?\}", content, re.DOTALL)
        # ruleMatches = re.findall(r"^\s*(?:private|global)?\s*(?:private|global)?\s*rule\s+([a-zA-Z0-9_]+)", content, re.DOTALL)

        if category not in ruleList:
          ruleList[category] = []

        for rule in ruleMatches:
          ruleList[category].append(rule)

  return ruleList

# # Scoring system based on rule structure
# def scoreYaraRule(ruleText):
#   score = 0

#   # --- Meta Scoring ---
#   metaMatches = re.findall(r'meta:\s*(.*?)\s*(strings:|condition:)', ruleText, re.DOTALL)
#   if metaMatches:
#     metaBlock = metaMatches[0][0]

#     score += 10
#     if re.search(r'description\s*=', metaBlock):
#       score += 5
#     if re.search(r'reference\s*=', metaBlock):
#       score += 5
#     if re.search(r'malwareFamily\s*=', metaBlock, re.IGNORECASE):
#       score += 5
#     if re.search(r'author\s*=', metaBlock):
#       score += 3
#     if re.search(r'date\s*=', metaBlock):
#       score += 2

#   # --- Strings Section ---
#   stringsMatch = re.findall(r'strings:\s*(.*?)\s*condition:', ruleText, re.DOTALL)
#   if stringsMatch:
#     stringsBlock = stringsMatch[0]
#     stringEntries = re.findall(r'\$[a-zA-Z0-9_]+\s*=\s*.*', stringsBlock)
#     stringCount = len(stringEntries)

#     if stringCount > 0:
#       score += 10
#       score += min(stringCount * 2, 10)

#       for s in stringEntries:
#         modifiers = re.findall(r'\b(ascii|nocase|wide|fullword|xor)\b', s)
#         score += min(len(modifiers), 5)

#   # --- Condition ---
#   conditionMatch = re.search(r'condition:\s*(.*?)\s*\}', ruleText, re.DOTALL)
#   if conditionMatch:
#     condition = conditionMatch.group(1)
#     score += 10
#     logicOps = re.findall(r'\b(and|or|not)\b', condition, re.IGNORECASE)
#     score += min(len(logicOps), 10)

#     if re.search(r'\bfor\s+(all|any|\d+\s+of)\b', condition):
#       score += 10

#   # --- Imports ---
#   importMatches = re.findall(r'import\s+"(.*?)"', ruleText)
#   if importMatches:
#     score += min(len(importMatches) * 2, 10)

#   # --- External Variables ---
#   externals = re.findall(r'externals?:\s*.*', ruleText)
#   if externals:
#     score += min(len(externals), 5)

#   # --- Rule-level Quality ---
#   if re.match(r'\s*(private\s+)?rule\s+', ruleText):
#     score += 2
#   if re.search(r'tags\s*=', ruleText):
#     tagMatches = re.findall(r'tags\s*=\s*\[(.*?)\]', ruleText)
#     if tagMatches:
#       tags = tagMatches[0].split(',')
#       score += min(len(tags), 5)

#   return min(score, 100)

# Scoring system based on https://github.com/Neo23x0/YARA-Style-Guide
def scoreYaraRule(ruleText):
  score = 0

  # --- Meta Section ---
  metaMatch = re.search(r'meta:\s*(.*?)\s*(strings:|condition:)', ruleText, re.DOTALL)
  if metaMatch:
    metaBlock = metaMatch.group(1)
    score += 10  # base meta score

    if re.search(r'description\s*=', metaBlock):
      score += 10
    if re.search(r'reference\s*=', metaBlock):
      score += 5
    if re.search(r'malwareFamily\s*=', metaBlock, re.IGNORECASE):
      score += 5
    if re.search(r'author\s*=', metaBlock):
      score += 3
    if re.search(r'date\s*=', metaBlock):
      score += 2

  # --- Strings Section ---
  stringsMatch = re.search(r'strings:\s*(.*?)\s*condition:', ruleText, re.DOTALL)
  if stringsMatch:
    stringsBlock = stringsMatch.group(1)
    strings = re.findall(r'\$[a-zA-Z0-9_]+\s*=\s*.*', stringsBlock)
    stringCount = len(strings)

    if stringCount > 0:
      score += 10
      score += min(stringCount * 2, 10)  # max +10 for # of strings

      for stringLine in strings:
        if re.search(r'\bxor\b', stringLine):
          score += 2
        if re.search(r'\b(wide|ascii|nocase|fullword)\b', stringLine):
          score += 1  # reward each modifier (up to 5 total)
    
  # --- Condition Section ---
  conditionMatch = re.search(r'condition:\s*(.*?)\s*\}', ruleText, re.DOTALL)
  if conditionMatch:
    conditionBlock = conditionMatch.group(1)

    score += 10  # base score for condition presence

    if re.search(r'\b(for\s+all|for\s+any|\d+\s+of)\b', conditionBlock):
      score += 10
    if re.search(r'\b(and|or|not)\b', conditionBlock, re.IGNORECASE):
      logicOps = re.findall(r'\b(and|or|not)\b', conditionBlock, re.IGNORECASE)
      score += min(len(logicOps), 5)

  # --- Import Section ---
  importMatches = re.findall(r'import\s+"[^"]+"', ruleText)
  if importMatches:
    score += min(len(importMatches) * 2, 10)

  # --- External Variables ---
  externalMatches = re.findall(r'external\s+[a-zA-Z0-9_]+', ruleText)
  score += min(len(externalMatches), 5)

  # --- Tags Section ---
  tagsMatch = re.search(r'tags\s*=\s*\[(.*?)\]', ruleText)
  if tagsMatch:
    tags = [tag.strip() for tag in tagsMatch.group(1).split(',')]
    score += min(len(tags), 5)

  # --- Rule Declaration ---
  if re.match(r'\s*(private\s+)?rule\s+\w+', ruleText):
    score += 2

  return min(score, 100)

def scoreYaraRuleJson(rule):
  score = 0

  # --- Meta Scoring ---
  meta = rule.get("meta", {})
  if meta:
    score += 10
    if "description" in meta:
      score += 5
    if "reference" in meta:
      score += 5
    if "malwareFamily" in meta:
      score += 5
    if "author" in meta:
      score += 3
    if "date" in meta:
      score += 2

  # --- Strings Section ---
  strings = rule.get("strings", {})
  stringCount = len(strings)
  if stringCount > 0:
    score += 10
    score += min(stringCount * 2, 10)
    for val in strings.values():
      modifiers = val.get("modifiers", []) if isinstance(val, dict) else []
      score += min(len(modifiers), 5)

  # --- Condition ---
  condition = rule.get("condition", "")
  if condition:
    score += 10
    logicOps = re.findall(r'\b(and|or|not)\b', condition, re.IGNORECASE)
    score += min(len(logicOps), 10)
    if re.search(r'\bfor\s+(all|any|\d+\s+of)\b', condition):
      score += 10

  # --- Imports ---
  imports = rule.get("imports", [])
  if imports:
    score += min(len(imports) * 2, 10)

  # --- External Variables ---
  externalVars = rule.get("externalVariables", [])
  if externalVars:
    score += min(len(externalVars), 5)

  # --- Rule-level Quality ---
  if rule.get("isPrivate"):
    score += 2
  if rule.get("tags"):
    score += min(len(rule["tags"]), 5)

  return min(score, 100)

def assignScoreToRules(ruleList, outputPath):
  results = []
  uniqueScores = set()
  ruleCount = 0

  try:
    for _, rules in ruleList.items():
      for ruleContent in rules:
        match = re.search(r'\brule\s+(\w+)', ruleContent)
        ruleName = match.group(1) if match else "unknown"
        
        score = scoreYaraRule(ruleContent)
        
        results.append({
          "ruleName": ruleName,
          "yaraRule": ruleContent.strip(),
          "score": score
        })
        uniqueScores.add(score)
        ruleCount += 1

    os.makedirs(os.path.dirname(outputPath), exist_ok=True)
    with open(outputPath, 'w') as jsonFile:
      json.dump(results, jsonFile, indent=2)

    return uniqueScores, ruleCount

  except FileNotFoundError:
    print(f"{Colors.red}Error: Directory {directoryPath} not found.{Colors.reset}")
  except Exception as e:
    print(f"{Colors.red}An error occurred: {e}{Colors.reset}")

def main():
  outputDirectory = "confidence"
  outputFile = "yara.confidence.scores.json"

  parser = argparse.ArgumentParser(
    description="Assign confidence score to YARA Rules",
    epilog="\nExample: python assignConfidenceToYaraRules.py -D ./rules"
  )
  parser.add_argument("-D", "--directory", help="Directory with YARA rule files", required=True)
  args = parser.parse_args()
  rulesDir = args.directory

  reset(outputDirectory)
  ensureDirectoryExists(rulesDir)

  outputFilePath = os.path.join(outputDirectory, outputFile)
  
  # Read rules
  print(f"Reading YARA rules from directory {Colors.blue}{rulesDir}{Colors.reset}...")
  yaraRuleList = readYaraFiles(rulesDir)

  if not yaraRuleList:
    print(f"No categorized YARA rules found. Please check the input directory.")
    exit(1)

  uniqueScores, ruleCount = assignScoreToRules(yaraRuleList, outputFilePath)

  print(f"\nTotal Rules Processed: {Colors.greenBold}{ruleCount}{Colors.reset}")
  print(f"\n{Colors.yellowBold}Unique Confidence Scores{Colors.reset}:")
  print(sorted(uniqueScores))
  print(f"\nConfidence JSON output written to {Colors.blueBold}{outputFilePath}{Colors.reset}.\n")


if __name__ == "__main__":
  main()

