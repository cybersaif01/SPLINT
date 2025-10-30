import yara
import os

rules_dir = "yara_rules"
rule_files = [
    os.path.join(rules_dir, f)
    for f in os.listdir(rules_dir)
    if f.endswith(".yar") or f.endswith(".yara")
]

yara_rules = yara.compile(filepaths={f"r{i}": f for i, f in enumerate(rule_files)})

def scan_files(filepath, rules):
    try:
        return rules.match(filepath)
    except Exception as e:
        print(f"[!] Error during YARA scan: {e}")
        return []
