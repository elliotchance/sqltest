import glob
import yaml
import os.path
import time
import bnf
import sys

result_tests = []

raw_rules = bnf.parse_bnf_file('standards/2016/bnf.txt')
rules = bnf.analyze_rules(raw_rules)

if len(sys.argv) == 1:
    files = glob.glob("standards/2016/*.yml")
else:
    files = sys.argv[1:]

for feature_file_path in sorted(files):
    basename = os.path.basename(feature_file_path)
    if basename[0].upper() != basename[0] or '.tests.yml' in basename:
        continue

    print(basename)

    feature_file = open(feature_file_path, "r")
    tests = yaml.load_all(feature_file)

    for test in tests:
        rule_names = test['examples']['bnf']
        if not isinstance(rule_names, list):
            rule_names = [rule_names]

        exclude = []
        if 'exclude' in test['examples']:
            exclude = test['examples']['exclude']

        for rule_name in rule_names:

            overrides = {}
            for override in test['examples']:
                overrides[override] = bnf.ASTKeyword(str(test['examples'][override]))
            examples = bnf.get_paths_for_rule(rules, rule_name, overrides, exclude)

            for example in examples:
                test_id = basename.split('.')[0].replace('-', '_').lower() + "_t" + str(len(result_tests))
                sql = test['sql'].replace('$TN$', test_id)
                result_tests.append({
                    'id': test_id,
                    'feature': basename[:-4],
                    'sql': sql.replace('$EXAMPLE$', example)
                })

    output_file_path = feature_file_path[:-4] + ".tests.yml"
    with open(output_file_path, "w") as output_file:
        output_file.write(yaml.dump_all(result_tests, default_flow_style=False))
