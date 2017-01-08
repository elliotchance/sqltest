# -*- coding: utf-8 -*-

import glob
import yaml
import os.path
import time
import bnf
import sys
import sqlite3

def feature_id_from_file_path(file_path):
    return file_path.split('/')[-1][:-4]

def output_file(feature_file_path):
    return feature_file_path[:-4] + ".tests.yml"

def all_features_with_tests(standard):
    all_files = glob.glob("standards/%s/*.yml" % standard)
    feature_files = []
    for feature_file_path in sorted(all_files):
        basename = os.path.basename(feature_file_path)
        if basename[0].upper() != basename[0] or '.tests.yml' in basename:
            continue

        feature_files.append(feature_file_path)

    return feature_files

def get_rules(standard):
    raw_rules = bnf.parse_bnf_file('standards/%s/bnf.txt' % standard)
    return bnf.analyze_rules(raw_rules)

def generate_tests(feature_file_path):
    feature_file = open(feature_file_path, "r")
    tests = yaml.load_all(feature_file)
    basename = os.path.basename(feature_file_path)
    result_tests = []

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

    with open(output_file(feature_file_path), "w") as f:
        f.write(yaml.dump_all(result_tests, default_flow_style=False))

standard = '2016'
rules = get_rules(standard)
feature_file_paths = all_features_with_tests(standard)
test_files = {}

for feature_file_path in feature_file_paths:
    feature_id = feature_id_from_file_path(feature_file_path)
    generated_file_path = output_file(feature_file_path)
    test_files[feature_id] = generated_file_path

    if os.path.isfile(generated_file_path):
        continue

    print("Generating tests for %s" % feature_id)
    generate_tests(feature_file_path)

# Prepare the database
db_file = 'test.db'
if os.path.isfile(db_file):
    os.remove(db_file)
conn = sqlite3.connect(db_file)
c = conn.cursor()

# Run the tests
for feature_id in test_files:
    file_path = test_files[feature_id]
    test_file = open(file_path, "r")
    tests = list(yaml.load_all(test_file))

    print('\n%s: %s tests' % (feature_id, len(tests)))

    for test in tests:
        did_pass = True
        try:
            c.execute(test['sql'])
        except sqlite3.OperationalError:
            did_pass = False

        if did_pass:
            print('  ✓ %s' % test['sql'])
        else:
            print('  ✗ %s' % test['sql'])

#conn.commit()
conn.close()
