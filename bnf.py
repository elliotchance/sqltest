import re
import pprint
import sys
import argparse

def get_override(rule_name):
    global args

    try:
        return getattr(args, rule_name)
    except:
        return None

def resolve_paths(paths):
    new_paths = []
    for path in paths:
        search = re.search(r'(.*?)\[(.*)\](.*?)', path)

        path = path.replace('...', '')

        if '[' in path:
            left, right = path.find('['), path.rfind(']') + 1
            new_paths.extend(resolve_paths([
                path[:left] + path[right:],
                path[:left] + path[left + 1:right - 1] + path[right:]
            ]))
        else:
            new_paths.append(path.replace('  ', ' ').strip())

    return new_paths

def resolve_rule(rules, rule_name):
    override = get_override(rule_name.replace(' ', '_'))
    if override:
        return [override]

    paths = rules[rule_name]

    while True:
        # Find a substitution
        sub = None
        for path in paths:
            search = re.search(r'<([^>]+)>', path)

            if search:
                sub = search.group(0)
                break

        # Complete when there are no more substitutions
        if sub is None:
            return paths

        # Otherwise, perform substitution
        new_paths = []
        for path in paths:
            sub_resolve = resolve_rule(rules, sub[1:-1])
            
            for r in sub_resolve:
                s = path.replace(sub, r)
                if s not in new_paths:
                    new_paths.append(s)

        paths = new_paths

    return new_paths

with open('standards/ISO_IEC_9075-2-2016-E_Foundation/bnf.txt', 'r') as bnf_file:
    # Extract the rules
    rules = {}
    current_rule = None
    for line in bnf_file.readlines():
        if '::=' in line:
            search = re.search(r'<(.*)>\s*::=\s*(.*)\s*', line)
            rules[search.group(1)] = search.group(2)
            current_rule = search.group(1)
        else:
            rules[current_rule] += line.strip()

    # Split the rules into individual paths
    for rule_name in rules:
        rules[rule_name] = resolve_paths([x.strip() for x in rules[rule_name].split('|')])

parser = argparse.ArgumentParser(description='Working with BNF grammars.')
parser.add_argument('rules', metavar='rule', type=str, nargs='?',
                    help='a BNF rule name')

for rule_name in rules:
    if len(rules[rule_name]) > 1 or '<' in ''.join(rules[rule_name]):
        parser.add_argument('--%s' % rule_name.replace(' ', '-'))

args = parser.parse_args()

def resolve_rule_with_options(rule_name, options):
    global rules, args

    for option in options:
        setattr(args, option, str(options[option]))

    return resolve_rule(rules, rule_name)

if __name__ == '__main__':
    if args.rules:
        for path in resolve_rule(rules, args.rules):
            print(path)
    else:
        pprint.pprint(rules)
