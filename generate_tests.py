import glob
import yaml
import os.path
import time
import bnf

result_tests = []

raw_rules = bnf.parse_bnf_file('standards/2016/bnf.txt')
rules = bnf.analyze_rules(raw_rules)

files = glob.glob("standards/2016/*.yml")
for feature_file_path in sorted(files):
    basename = os.path.basename(feature_file_path)
    if basename[0].upper() != basename[0]:
        continue

    print(basename)

    feature_file = open(feature_file_path, "r")
    tests = yaml.load_all(feature_file)

    for test in tests:
        rule_name = test['examples']['bnf']
        overrides = {}
        for override in test['examples']:
            overrides[override] = bnf.ASTKeyword(str(test['examples'][override]))
        examples = bnf.get_paths_for_rule(rules, rule_name, overrides)

        for example in examples:
            test_id = basename.split('.')[0].lower() + "_t" + str(len(result_tests))
            sql = test['sql'].replace('$TN$', test_id)
            result_tests.append({
                'id': test_id,
                'feature': basename[:-4],
                'sql': sql.replace('$EXAMPLE$', example)
            })

print(yaml.dump_all(result_tests, default_flow_style=False))
