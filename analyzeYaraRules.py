from datetime import datetime
import argparse
import json
import os
import re
import shutil
import sys

# Default categories and associated keywords
defaultCategories = {
  "malware": "malware, trojan, ransomware, virus, worm, infostealer",
  "exploit": "exploit, vulnerability, attack, privilege, escalation, cve",
  "network": "network, traffic, packet, dns, http, ssl, c2, command-and-control",
  "document": "document, pdf, doc, docx, office, macro, xls, ppt",
  "packer": "packer, obfuscation, cryptor, encoded, polymorphic",
  "crypto": "crypto, bitcoin, wallet, blockchain, ethereum, monero",
  "keylogger": "keylogger, keystroke, credentials, password, steal"
}

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

def setupOutputDirectory(directory):
  if os.path.exists(directory):
    shutil.rmtree(directory)
  os.makedirs(directory, exist_ok=True)

def getAllYaraFiles(directory):
  yaraFiles = []
  for root, _, files in os.walk(directory):
    for file in files:
      if file.endswith('.yar') or file.endswith('.yara'):
        yaraFiles.append(os.path.join(root, file))
  return yaraFiles

def detectDuplicates(yaraFiles, duplicateFilePath):
  ruleNames = {}
  rulesProcessed = 0
  filesProcessed = 0
  duplicates = []

  rulePattern = re.compile(r'^\s*rule\s+([a-zA-Z0-9_]+)')

  for file in yaraFiles:
    filesProcessed += 1
    try:
      with open(file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
          match = rulePattern.match(line)
          if match:
            rulesProcessed += 1
            ruleName = match.group(1)
            if ruleName in ruleNames:
              print(f"\n{Colors.redBold}[!]{Colors.reset} Duplicate rule found: {Colors.greenBold}{ruleName}{Colors.reset} in file {Colors.yellowBold}{file}{Colors.reset}")
              duplicates.append(f"{datetime.utcnow()} Duplicate rule found: {ruleName} in file {file}")
            else:
              ruleNames[ruleName] = file
    except Exception as e:
      print(f"{Colors.redBold}[!]{Colors.reset} Error reading file {file}: {e}")

  if duplicates:
    with open(duplicateFilePath, 'w', encoding='utf-8') as dupFile:
      dupFile.write('\n'.join(duplicates))
  elif os.path.isfile(duplicateFilePath):
    os.remove(duplicateFilePath)

  return filesProcessed, rulesProcessed

def injectMetaCategory(ruleContent, category, matchedKeyword):
  rulePattern = re.compile(r'^\s*((?:private|global)?\s*(?:private|global)?\s*rule\s+[a-zA-Z0-9_]+)', re.MULTILINE)
  parts = rulePattern.split(ruleContent)

  if not parts or len(parts) < 2:
    return ruleContent # No rule detected

  rebuilt = parts[0] # Anything before the first rule (e.g., includes or comments)

  for i in range(1, len(parts), 2):
    ruleHeader = parts[i]   # full "private rule Something"
    ruleBody = parts[i + 1] # rule body starts after the header

    if 'meta:' in ruleBody:
      metaStart = ruleBody.find('meta:')
      stringsStart = ruleBody.find('strings:', metaStart)
      if stringsStart == -1:
        stringsStart = ruleBody.find('condition:', metaStart)
      if stringsStart != -1:
        beforeMeta = ruleBody[:stringsStart]
        afterMeta = ruleBody[stringsStart:]

        if 'category' not in beforeMeta and 'matchedKeyword' not in beforeMeta:
          injected = f'  category = "{category}"\n  matchedKeyword = "{matchedKeyword}"\n'
          ruleBody = beforeMeta.rstrip() + '\n' + injected + afterMeta
        else:
          ruleBody = re.sub(r'(category\s*=\s*".*?")', f'category = "{category}"', ruleBody)
          ruleBody = re.sub(r'(matchedKeyword\s*=\s*".*?")', f'matchedKeyword = "{matchedKeyword}"', ruleBody)
    else:
      ruleBody = ruleBody.replace(
        'strings:',
        f'meta:\n  category = "{category}"\n  matchedKeyword = "{matchedKeyword}"\n  strings:',
        1
      )

    rebuilt += ruleHeader + ruleBody

  return rebuilt

def categorizeRules(yaraFiles, checkedDir, keywordCategories):
  categorizedCount = 0
  uncategorizedCount = 0

  # Precompile keywords once
  compiledCategories = {}
  for cat, keywords in keywordCategories.items():
    compiledCategories[cat] = [re.compile(re.escape(k.strip()), re.IGNORECASE) for k in keywords.split(',')]

  # Create directories for each category and 'uncategorized' if not already created
  for cat in keywordCategories.keys():
    os.makedirs(os.path.join(checkedDir, cat), exist_ok=True)
  os.makedirs(os.path.join(checkedDir, 'uncategorized'), exist_ok=True)

  for file in yaraFiles:
    with open(file, 'r', encoding='utf-8', errors='ignore') as f:
      lines = f.readlines()
    ruleContent = ''.join(lines)
    ruleContentLower = ruleContent.lower()

    fileName = os.path.basename(file)
    fileNameNoExt = os.path.splitext(fileName)[0].lower()
    parentDir = os.path.basename(os.path.dirname(file)).lower()

    for line in lines:
      match = re.match(r'^\s*(?:private|global)?\s*(?:private|global)?\s*rule\s+([a-zA-Z0-9_]+)', line)
      if match:
        ruleName = match.group(1)
        ruleNameLower = ruleName.lower()
        category = 'uncategorized'
        matchedKeyword = None
        folderMatched = False

        # Check if folder name matches any category keyword
        for cat, patterns in compiledCategories.items():
          for pattern in patterns:
            if pattern.fullmatch(parentDir):
              category = cat
              matchedKeyword = pattern.pattern
              folderMatched = True
              break
          if folderMatched:
            break

        # Check rule name, file name, content
        if not folderMatched:
          for cat, patterns in compiledCategories.items():
            for pattern in patterns:
              if pattern.search(ruleNameLower) or pattern.search(fileNameNoExt) or pattern.search(ruleContentLower):
                category = cat
                matchedKeyword = pattern.pattern
                break
            if category != 'uncategorized':
              break

        if category == 'uncategorized':
          category = f"uncategorized/{parentDir}"
          os.makedirs(os.path.join(checkedDir, category), exist_ok=True)
          uncategorizedCount += 1
        else:
          categorizedCount += 1

        ruleContent = injectMetaCategory(ruleContent, category, matchedKeyword)

        destPath = os.path.join(checkedDir, category, fileName)
        with open(destPath, 'w', encoding='utf-8') as outputFile:
          outputFile.write(ruleContent)

        # Print out feedback on categorization
        print(
          f"{Colors.greenBold}[+]{Colors.reset} Categorized rule " 
          f"{Colors.blue}#{categorizedCount}{Colors.reset} "
          f"{Colors.green}{ruleName}{Colors.reset} from "
          f"{Colors.yellow}{file}{Colors.reset} as "
          f"{Colors.yellowBold}{category}{Colors.reset}"
        )

  return categorizedCount, uncategorizedCount

def dumpCategoriesToFile(keywordCategories, file):
  with open(file, "w") as f:
    json.dump(keywordCategories, f, indent=2)
  print(f"{Colors.greenBold}[*]{Colors.reset} Categories written to {Colors.yellow}{file}{Colors.reset}")
  sys.exit(0)

def loadCategoriesFromFile(path):
  if not os.path.isfile(path):
    print(f"{Colors.redBold}Error{Colors.reset}: Categories file '{path}' not found!")
    sys.exit(1)
  try:
    with open(path, 'r', encoding='utf-8') as f:
      data = json.load(f)
    print(f"{Colors.greenBold}[*]{Colors.reset} Loaded categories from {Colors.yellow}{path}{Colors.reset}")
    return data
  except Exception as e:
    print(f"{Colors.redBold}Error{Colors.reset}: Failed to load categories file. {str(e)}")
    sys.exit(1)

def fetchYaraCategories():
  return defaultCategories

def processYaraRules(rulesDir, outputDir, duplicateFile, categories=defaultCategories):
  print(f"\n{Colors.greenBold}[*]{Colors.reset} Setting up {Colors.yellowBold}{outputDir}{Colors.reset}...")

  setupOutputDirectory(outputDir)

  print(f"{Colors.greenBold}[*]{Colors.reset} Checking for duplicate YARA rules...")
  yaraFiles = getAllYaraFiles(rulesDir)
  filesProcessed, rulesProcessed = detectDuplicates(yaraFiles, duplicateFile)

  print(f"\n{Colors.greenBold}[*]{Colors.reset} Duplicate scan completed. Results saved in {Colors.yellow}{duplicateFile}{Colors.reset}")
  print(f"\n{Colors.greenBold}[*]{Colors.reset} Categorizing YARA rules...\n")

  # categorizeRules(yaraFiles, outputDir, categories)
  categorizedCount, uncategorizedCount = categorizeRules(yaraFiles, outputDir, categories)

  print(f"\n{Colors.greenBold}[*]{Colors.blueBold}Processing Summary:{Colors.reset}")
  print(f"{Colors.greenBold}[*]{Colors.reset} Files Processed: {Colors.blue}{filesProcessed}{Colors.reset}")
  print(f"{Colors.greenBold}[*]{Colors.reset} Rules Processed: {Colors.yellow}{rulesProcessed}{Colors.reset}")
  print(f"{Colors.greenBold}[*]{Colors.reset} Rules Categorized: {Colors.green}{categorizedCount}{Colors.reset}")
  print(f"{Colors.yellowBold}[!]{Colors.reset} Uncategorized rules: {Colors.red}{uncategorizedCount}{Colors.reset}")
  print(f"\n{Colors.greenBold}[*]{Colors.reset} Categorization completed. Categorized rules are stored in {Colors.yellow}{outputDir}{Colors.reset}/")

def main():
  duplicateFile = "yara.rules.duplicate.txt"
  outputCategoriesFile = "categories.json"
  outputCategorizedDir = "categorizedRules"

  parser = argparse.ArgumentParser(
    description="YARA Rule Categorizer and Duplicate Finder",
    epilog="Example: python analyzeYaraRules.py -D ./rules --categories custom.json"
  )

  parser.add_argument("-D", "--directory", help="Directory with YARA rule files")
  parser.add_argument("-o", "--output", help="Output directory for categorized rules", default=outputCategorizedDir)
  parser.add_argument("--dump", action="store_true", help="Dump keyword categories to categories.json and exit")
  parser.add_argument("--categories", help="Path to custom keyword category JSON file")

  args = parser.parse_args()

  keywordCategories = defaultCategories

  if args.dump:
    categoriesFilePath = os.path.join(outputCategorizedDir, outputCategoriesFile)
    dumpCategoriesToFile(keywordCategories, categoriesFilePath)

  if args.categories:
    keywordCategories = loadCategoriesFromFile(args.categories)

  if not args.directory:
    parser.error("You must specify -D/--directory unless using --dump.")

  rulesDir = args.directory
  outputDir = args.output

  processYaraRules(rulesDir, outputDir, duplicateFile, keywordCategories)

if __name__ == "__main__":
  main()
