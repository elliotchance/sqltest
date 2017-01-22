# -*- coding: utf-8 -*-

import glob
import yaml
import os.path
import time
import bnf
import sys
import sqlite3
import cgi
from jinja2 import Template
import pprint

def load_db_config(name, version):
    features_file = open("dbs/%s/%s.yml" % (name, version), "r")
    return yaml.load(features_file)

def get_all_features(standard):
    features_file = open("standards/%s/features.yml" % standard, "r")
    all_features = yaml.load(features_file)

    for group in ('mandatory', 'optional'):
        for feature_id in all_features[group]:
            all_features[group][feature_id] = {
                'description': all_features[group][feature_id]
            }

    return all_features

def feature_id_from_file_path(file_path):
    return file_path.split('/')[-1][:-4]

def output_file(feature_file_path):
    return feature_file_path[:-4] + ".tests.yml"

def all_features_with_tests(standard):
    all_files = glob.glob("standards/%s/[EF]/*.yml" % standard)
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

def generate_tests(feature_file_path, db_config):
    feature_file = open(feature_file_path, "r")
    tests = yaml.load_all(feature_file)
    basename = os.path.basename(feature_file_path)
    result_tests = []
    test_number = 0

    for test in tests:
        test_number += 1

        override = {}
        if 'override' in test:
            override = test['override']
        for name in override:
            if override[name] is None:
                override[name] = ''
            override[name] = bnf.ASTKeyword(str(override[name]))

        exclude = []
        if 'exclude' in test:
            exclude = test['exclude']

        if isinstance(test['sql'], list):
            test['sql'] = ';'.join(test['sql'])

        sqls = bnf.get_paths_for_rule(rules, test['sql'], override, exclude)

        for rule_number in xrange(0, len(sqls)):
            test_id = '%s_%02d_%02d' % (
                basename.split('.')[0].replace('-', '_').lower(),
                test_number, rule_number + 1
            )

            sqls[rule_number] = sqls[rule_number].replace('TN', 'TABLE_%s' % test_id.upper())
            sqls[rule_number] = sqls[rule_number].replace('ROLL1', 'ROLL_%s' % test_id.upper())
            sqls[rule_number] = sqls[rule_number].replace('CURSOR1', 'CUR_%s' % test_id.upper())
            sqls[rule_number] = sqls[rule_number].replace('CONSTRAINT1', 'CONST_%s' % test_id.upper())
            sqls[rule_number] = sqls[rule_number].replace('VIEW1', 'VIEW_%s' % test_id.upper())

            split_sql = sqls[rule_number].split(' ; ')
            if len(split_sql) == 1:
                split_sql = split_sql[0]

            result_tests.append({
                'id': test_id,
                'feature': basename[:-4],
                'sql': split_sql
            })

    with open(output_file(feature_file_path), "w") as f:
        f.write(yaml.dump_all(result_tests, default_flow_style=False))

db_config = load_db_config('SQLite3', '3.16')
standard = '2016'
rules = get_rules(standard)
feature_file_paths = all_features_with_tests(standard)
test_files = {}

for feature_file_path in feature_file_paths:
    feature_id = feature_id_from_file_path(feature_file_path)
    generated_file_path = output_file(feature_file_path)
    test_files[feature_id] = {
        'path': generated_file_path
    }

    # if os.path.isfile(generated_file_path):
    #    continue

    print("Generating tests for %s" % feature_id)
    generate_tests(feature_file_path, db_config)

# Run the tests
for feature_id in sorted(test_files):
    file_path = test_files[feature_id]['path']
    test_file = open(file_path, "r")
    tests = list(yaml.load_all(test_file))

    test_files[feature_id]['pass'] = 0
    test_files[feature_id]['fail'] = 0

    print('%s: %s tests' % (feature_id, len(tests)))

    for test in tests:
        did_pass = True

        if not isinstance(test['sql'], list):
            test['sql'] = [ test['sql'] ]

        error = None
        try:
            conn = sqlite3.connect(':memory:')
            conn.isolation_level = None

            c = conn.cursor()
            for sql in test['sql']:
                # Fix keywords
                for keyword in db_config['keywords']:
                    sql = sql.replace(keyword, db_config['keywords'][keyword])

                c.execute(sql)

            # conn.commit()
            conn.close()
        except sqlite3.OperationalError as e:
            error = e
            did_pass = False

        if did_pass:
            test_files[feature_id]['pass'] += 1
            print('\33[32m  ✓ %s\33[0m\n' % '\n    '.join(test['sql']))
        else:
            test_files[feature_id]['fail'] += 1
            print('\33[31m  ✗ %s\n    ERROR: %s\33[0m\n' % ('\n    '.join(test['sql']), error))

# Merge the rules with the original features
all_features = get_all_features(standard)
for feature_id in test_files:
    all_features['mandatory'][feature_id].update(test_files[feature_id])

def get_html_color_for_pass_rate(pass_rate):
    # The returned weighted gradient goes from red at 0% to yellow at 75% to
    # green at 100%. It is weighted because what feels like a "pass" where it
    # start transitioning to green should really start at 75% rather than 50%.
    if pass_rate <= 0.75:
        r, g, b = (255, 255 * pass_rate * 1.333, 0)
    else:
        r, g, b = (255 - (255 * (pass_rate - 0.75) * 4), 255, 0)
    
    return '#%x%x%x' % (r, g, b)

# Generate HTML report

with open("templates/report.html", "r") as report_template:
    t = Template(report_template.read())

    feats = {
        'mandatory': [],
        'optional': []
    }

    total_tests = 0
    total_passed = 0
    
    for category in ('mandatory', 'optional'):
        for feature_id in sorted(all_features[category]):
            f = all_features[category][feature_id]

            if 'pass' in all_features[category][feature_id]:
                f['pass'] = all_features[category][feature_id]['pass']
                f['fail'] = all_features[category][feature_id]['fail']
            else:
                f['pass'] = 0
                f['fail'] = 0

            if '-' not in feature_id and ('%s-01' % feature_id) in all_features[category]:
                for fid in sorted(all_features[category]):
                    if fid.startswith('%s-' % feature_id) and \
                    'pass' in all_features[category][fid]:
                        f['pass'] += all_features[category][fid]['pass']
                        f['fail'] += all_features[category][fid]['fail']

                if f['pass'] == 0 and f['fail'] == 0:
                    del f['pass']
                    del f['fail']

            percent = '&nbsp;'
            color = 'grey'
            if 'pass' in f and (f['pass'] + f['fail']) > 0:
                if f['pass'] == 0:
                    pass_rate = 0
                else:
                    pass_rate = float(f['pass']) / (float(f['pass']) + float(f['fail']))

                percent = '%01.0d%% (%d/%d)' % (pass_rate * 100, f['pass'],
                    int(f['pass']) + int(f['fail']))
                color = get_html_color_for_pass_rate(pass_rate)

                if '-' not in feature_id:
                    total_tests += f['pass'] + f['fail']
                    total_passed += f['pass']

            feats[category].append({
                'id': feature_id,
                'description': cgi.escape(all_features[category][feature_id]['description']),
                'color': color,
                'percent': percent,
            })

    with open("report.html", "w") as report_file:
        db = {
            'name': 'SQLite3',
            'version': sqlite3.sqlite_version,
        }
        report_file.write(t.render(db=db, features=feats, int=int, len=len, total_tests=total_tests, total_passed=total_passed))
