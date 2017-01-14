import re
import pprint
import sys
import argparse
import yaml
import os.path
import copy
import itertools

# TODO:
# 
#   1. Change render() methods to json() and add option to CLI.
#   2. Clean up CLI docs so that each mode is documented separately.
#   3. See TODO below about resolving recusions at any level.

class RecursiveException(Exception):
    """Thrown when recursion is detected on a BNF rule."""

    def __init__(self, rule_name):
        Exception.__init__(self, 'Recursion on rule %s.' % rule_name)
        self.rule_name = rule_name

class DuplicateBNFRuleException(Exception):
    """Thrown when a BNF rule is found more than once in a file."""

    def __init__(self, rule_name):
        Exception.__init__(self, 'Rule <%s> redefined.' % rule_name)

class MissingBNFRuleException(Exception):
    """Thrown when a BNF rule is not found."""

    def __init__(self, rule_name):
        Exception.__init__(self, 'Rule <%s> is not defined.' % rule_name)

def parse_bnf_file(file_path):
    """Parse a BNF file and return the rule names and grammars."""

    rules = {}

    with open(file_path, 'r') as bnf_file:
        current_rule = None
        for line in bnf_file.readlines():
            if '::=' in line:
                search = re.search(r'<(.*)>\s*::=\s*(.*)\s*', line)
                current_rule = search.group(1)

                if current_rule in rules:
                    raise DuplicateBNFRuleException(current_rule)

                rules[current_rule] = search.group(2)
            else:
                rules[current_rule] += line.strip()

    return rules

def extract_subrules_from_grammar(grammar):
    """Extracts the subrules (surrounded by angle-brackets) from a grammar. The
    returned value will be a set so duplicate rule references will be
    removed."""

    try:
        return set(re.findall(r'<([^>]+)>', grammar))
    except TypeError:
        raise RuntimeError("Could not parse BNF grammar: %s" % grammar)

def recurse_rule(rules, rule_name, already_seen):
    """Used to find all the subrules and call the same method recursively until
    an end is reached or a RecursiveException is raised - either way to wind up
    the stack."""

    if rule_name in already_seen:
        raise RecursiveException(rule_name)
    already_seen.append(rule_name)
    subrules = extract_subrules_from_grammar(rules[rule_name])

    for subrule in subrules:
        recurse_rule(rules, subrule, copy.copy(already_seen))

def rule_is_recursive(rules, rule_name):
    """Tests whether a rule is recursive."""

    try:
        recurse_rule(rules, rule_name, [])

        return False
    except RecursiveException as e:
        return True

def next_token(grammar, offset):
    """Returns the next token in a BNF grammar. This is used by all_tokens()
    before the parsing happens."""

    s = ''
    try:
        # Skip any trailing whitespace before reading the next token
        while grammar[offset] == ' ':
            offset += 1

        if grammar[offset] == ';':
            return grammar[offset], offset + 1

        if grammar[offset] == '!':
            try:
                new_offset = grammar.index('\n', offset) + 1
            except ValueError:
                new_offset = len(grammar)
            return grammar[offset:new_offset], new_offset

        if grammar[offset] == "'" or grammar[offset] == '"':
            looking_for = grammar[offset]
            try:
                new_offset = grammar.index(looking_for, offset + 1) + 1
            except ValueError:
                new_offset = len(grammar)
            return grammar[offset:new_offset], new_offset

        if grammar[offset] == '.':
            return '...', offset + 3

        if grammar[offset] == '|' or \
            grammar[offset] == '(' or \
            grammar[offset] == ')' or \
            grammar[offset] == '[' or \
            grammar[offset] == ']' or \
            grammar[offset] == '{' or \
            grammar[offset] == '}' or \
            grammar[offset] == '=':
            return grammar[offset], offset + 1

        if grammar[offset] == '<':
            new_offset = grammar.index('>', offset) + 1
            return grammar[offset:new_offset], new_offset

        while ord('A') <= ord(grammar[offset].upper()) <= ord('Z') or \
            ord('0') <= ord(grammar[offset]) <= ord('9') or \
            grammar[offset] == '_' or grammar[offset] == '.' or \
            grammar[offset] == '-' or grammar[offset] == ',':
            s += grammar[offset]
            offset += 1

        if s == '':
            raise RuntimeError("Error at %s" % grammar[offset:])

        return s, offset
    except IndexError:
        if s != '':
            return s, offset
        return None, offset

class ASTTokens(list):
    """Represents a list of tokens. Each token may be a string or another AST
    type. This class exists mainly to allow the __str__() method on a list for
    easier rendering back to text."""

    def __str__(self):
        return ' '.join([str(item) for item in self])

    def resolve(self, rules, overrides, exclude):
        # The deepcopy() here is important becuase we don't want to mutate the
        # original rules which will be reused.
        choice = ASTChoice([copy.deepcopy(self)])
        did_modify = True

        while did_modify:
            did_modify = False

            for choice_idx in xrange(0, len(choice)):
                for token_idx in xrange(0, len(choice[choice_idx])):
                    if isinstance(choice[choice_idx][token_idx], ASTOptional):
                        # Add a new path to the choice, one without the option
                        # and the other one with the option.
                        choice.append(copy.deepcopy(choice[choice_idx]))
                        del choice[choice_idx][token_idx]
                        choice[-1][token_idx] = ASTTokens(choice[-1][token_idx])

                        did_modify = True
                        break
                    elif isinstance(choice[choice_idx][token_idx], ASTRule):
                        sub_paths = choice[choice_idx][token_idx].resolve(rules, overrides, exclude)

                        for sub_path in sub_paths:
                            choice.append(copy.deepcopy(choice[choice_idx]))
                            choice[-1] = ASTTokens(choice[-1][:token_idx] + sub_path + choice[-1][token_idx + 1:])

                        del choice[choice_idx]

                        did_modify = True
                        break
                    elif isinstance(choice[choice_idx][token_idx], ASTKeyword):
                        pass
                    elif isinstance(choice[choice_idx][token_idx], ASTTokens):
                        temp = choice[choice_idx]
                        choice[choice_idx] = ASTTokens(temp[:token_idx])
                        choice[choice_idx].extend(list(temp[token_idx]))
                        choice[choice_idx].extend(temp[token_idx + 1:])

                        did_modify = True
                        break
                    elif isinstance(choice[choice_idx][token_idx], ASTRepeat):
                        choice[choice_idx][token_idx] = ASTTokens(choice[choice_idx][token_idx])
                    elif isinstance(choice[choice_idx][token_idx], ASTGroup):
                        choice[choice_idx][token_idx] = choice[choice_idx][token_idx][0]

                        did_modify = True
                        break
                    elif isinstance(choice[choice_idx][token_idx], ASTSubChoice):
                        for subchoice in choice[choice_idx][token_idx]:
                            choice.append(copy.deepcopy(choice[choice_idx]))
                            choice[-1][token_idx] = ASTTokens(subchoice)

                        del choice[choice_idx]

                        did_modify = True
                        break
                    else:
                        raise RuntimeError(choice[choice_idx][token_idx].__class__)

        # Apply the excludes
        new_paths = []
        for path in choice:
            should_exclude = False
            for token in path:
                if str(token) in exclude:
                    should_exclude = True
                    break

            if not should_exclude:
                new_paths.append(path)
        choice = new_paths
        
        # One edge case is when we are dealing with the constructing numerical
        # values, if we were to resolve the paths for 'signed numeric literal'
        # we would get some values like: `+ . 2`, `+ . 2 E + 2`, ...
        # 
        # These numbers are correct from the point of view of the BNF but
        # (probably) no databases will understand or accept these so the spaces
        # must be removed.
        for choice_idx in xrange(0, len(choice)):
            choice[choice_idx] = str(choice[choice_idx])

            # Since almost all of the components of a constructed number are
            # optional it difficult in a single regex to find anything that
            # could be a number without catching general spaces.
            # 
            # Note: use ' ' instead of \s so that it doesn't catch new lines.
            choice[choice_idx] = re.sub(
                r'( |^)([+-]? ?[\d. ]{2,}) ?( ?E *[+-]? *\d+)?( |$)',
                lambda m: format_number(m),
                choice[choice_idx]
            )

            # Collapse character literals
            choice[choice_idx] = re.sub(
                r'\'([ \w]+)\'',
                lambda m: "'%s'" % m.group(1)[1:-1] if m.group(1)[0] == ' ' else "'%s'" % m.group(1),
                choice[choice_idx]
            )
            choice[choice_idx] = choice[choice_idx].replace("' '", "''")

        return choice

    def render(self):
        return '<tokens>%s</tokens>' % ''.join([x.render() for x in self])

def format_number(m):
    r = m.group(1)
    if m.group(2):
        r += m.group(2).replace(' ', '')
    if m.group(3):
        r += m.group(3).replace(' ', '')
    r += m.group(4)

    return r

class ASTRule:
    """Represents a rule enclosed with angle brackets."""

    def __init__(self, name):
        self.name = name

    def __str__(self):
        return '<' + self.name + '>'

    def render(self):
        return '<rule>%s</rule>' % self.name

    def resolve(self, rules, overrides, exclude):
        if self.name in overrides:
            return ASTTokens([[overrides[self.name]]])

        # TODO: recursive values can be resolve at any level, not just the top
        # level.
        # if rules[self.name]['recursive']:
        #     raise RuntimeError("Rule %s is recursive." % self)

        return rules[self.name]['ast']

class ASTChoice(list):
    """One or more options separated by a pipe (|). Each represents a different
    path for the BNF grammar."""

    def __str__(self):
        new_choices = []
        for item in self:
            r = ''
            line_length = 0
            for token in item:
                s = str(token) + ' '

                if line_length + len(s) >= 80:
                    r += '\n    '
                    line_length = 4

                line_length += len(s)
                r += s

            new_choices.append(r.strip())

        return '    ' + '\n  | '.join(new_choices)

    def render(self):
        return '<choices>%s</choices>' % ''.join([x.render() for x in self])

    def resolve(self, rules, overrides, exclude):
        new_choice = ASTChoice()

        for choice in self:
            new_choice.extend(choice.resolve(rules, overrides, exclude))

        return new_choice

class ASTSubChoice(list):
    """A ASTSubChoice is grammatically the same as a ASTChoice, however it is
    render back into one line rather than multiple lines."""
    def __str__(self):
        return '{ ' + ' | '.join([str(item) for item in self]) + ' }'

    def render(self):
        return '<subchoice>%s</subchoice>' % ''.join([x.render() for x in self])

class ASTOptional(list):
    """An optional part of the BNF is surrounded by square-brackets."""

    def __str__(self):
        part = str(ASTTokens(self))

        if len(self) == 1 and part[0] == '{' and part[-1] != '.':
            part = part[2:-2]

        return '[ ' + part + ' ]'

    def render(self):
        return '<optional>%s</optional>' % ''.join([x.render() for x in self])

class ASTGroup(list):
    """A group is a virtual container for more than one element. This is usually
    followed by an elipsis."""

    def __str__(self):
        return '{ ' + str(ASTTokens(self)) + ' }'

    def render(self):
        return '<group>%s</group>' % ''.join([x.render() for x in self])

class ASTRepeat(list):
    """Represents a token or ASTGroup that repeats one or more times."""

    def __str__(self):
        return str(ASTTokens(self)) + '...'

    def render(self):
        return '<repeat>%s</repeat>' % ', '.join([x.render() for x in self])

class ASTComment(str):
    """Comments are added when the value or BNF syntax cannot be represented. It
    could also be added to a valid BNF to clarify abiguities."""

    def __str__(self):
        return '!!' + str.__str__(self) + '\n'

    def render(self):
        return '<comment>%s</comment>' % str(self)

class ASTKeyword(str):
    def __str__(self):
        return str.__str__(self)

    def render(self):
        return '<keyword>%s</keyword>' % str(self)

def parse(tokens, eof=None, root=None):
    """Parse the tokens of a BNF grammar and return an AST."""

    if root is None:
        ast = ASTChoice()
    else:
        ast = root

    choice = ASTTokens()
    while True:
        try:
            token = tokens.next()
            if token == eof:
                raise StopIteration()
        except StopIteration:
            if choice:
                ast.append(choice)
            break

        if token == '[':
            p = parse(tokens, ']', ASTSubChoice())
            choice.append(ASTOptional([p]))
        elif token == '{':
            p = parse(tokens, '}', ASTSubChoice())
            choice.append(ASTGroup([p]))
        elif token == '...':
            choice[-1] = ASTRepeat([choice[-1]])
        elif token == '|':
            ast.append(choice)
            choice = ASTTokens()
        elif len(token) > 0 and token[0] == '<':
            result = ASTRule(token[1:-1])
            choice.append(result)
        else:
            choice.append(ASTKeyword(token))

    return ast

def all_tokens(grammar):
    """Lex a BNF grammar string and return all of the tokens."""

    tokens = ASTTokens()

    # There are a lot of symbols in the grammar that cause havoc with the
    # parser. We can identify these by them being short and not containing any
    # letters or numbers.
    if len(grammar.strip()) < 4 and not re.match(r'[a-z][A-Z][0-9]', grammar):
        tokens.append(ASTKeyword(grammar.strip()))
        return tokens

    offset = 0
    while True:
        token, offset = next_token(grammar, offset)
        if token is None:
            break

        tokens.append(token)

    return tokens

def analyze_rules(rules):
    """The raw BNF rules are analyzed and built into a dictionary where the rule
    name is the key and each element is an object contain metadata about that
    rule."""

    cache = {}
    
    # Some of the BNF rules are just too hard for the parser to understand so we
    # specify explicit values here.
    predefined_rules = {
        'doublequote symbol': '""',
        'vertical bar': '|',
        'less than operator': '<',
        'less than or equals operator': '<=',
        'not equals operator': '<>'
    }

    try:
        for rule_name in sorted(rules):
            if rule_name in predefined_rules:
                ast = ASTChoice([ASTTokens([ASTKeyword(predefined_rules[rule_name])])])
            else:
                tokens = all_tokens(rules[rule_name])
                ast = parse(iter(tokens))

            cache[rule_name] = {
                'recursive': rule_is_recursive(rules, rule_name),
                'ast': ast
            }
    except KeyError as e:
        raise MissingBNFRuleException(str(e)[1:-1])

    return cache

def resolve_rule(rules, rule_name, already_parsed, checking_for_recursion=None):
    override = get_override(rule_name.replace(' ', '_'))
    if override and len(already_parsed) > 1:
        return [override]

    if (checking_for_recursion and rule_name in already_parsed) \
        or (not checking_for_recursion and rules[rule_name]['recursive'] is True and len(already_parsed) > 1):
        raise RecursiveException('<%s> is recursive, you must provide a value for --%s' % (rule_name, rule_name.replace(' ', '-')))
    already_parsed.append(rule_name)

    paths = rules[rule_name]['paths']

    while True:
        # Find a substitution
        sub = None
        for path in paths:
            search = re.search(r'<([^<>]+)>', path)

            if search:
                sub = search.group(0)
                break

        # Complete when there are no more substitutions
        if sub is None:
            return paths

        # Otherwise, perform substitution
        new_paths = []
        for path in paths:
            sub_resolve = resolve_rule(rules, sub[1:-1], already_parsed, checking_for_recursion)
                
            for r in sub_resolve:
                s = path.replace(sub, r)
                if s not in new_paths:
                    new_paths.append(s)

        paths = new_paths

    return new_paths

def find_missing_rules(rules):
    # Find all the rule names by taking the rules already defined as keys and
    # then running through all the known grammars to find any other rules.
    rule_names = set(rules)

    for rule_name in rules:
        grammar = str(rules[rule_name]['ast'])
        rule_names.update(extract_subrules_from_grammar(grammar))

    return sorted(rule_names - set(rules))

def get_paths_for_rule(rules, rule, overrides, exclude):
    p = parse(iter(all_tokens(rule)))
    return sorted([str(s) for s in p.resolve(rules, overrides, exclude)])

def output_rule(rules, rule_name, overrides, exclude, output_paths, output_subrules):
    if output_paths:
        print('\n'.join(get_paths_for_rule(rules, rule_name, overrides, exclude)))
    else:
        # Render as BNF syntax
        rules_to_render = set([rule_name])
        if output_subrules:
            rules_to_render = get_subrules(rules, rule_name)

        for rule in rules_to_render:
            print('<%s> ::=\n%s\n' % (rule, str(rules[rule]['ast'])))

def get_subrules(rules, rule_name):
    all_rules = set([rule_name])
    did_update = True

    while did_update:
        did_update = False

        for r in all_rules:
            sub_rules = extract_subrules_from_grammar(str(rules[r]['ast']))

            if len(sub_rules - all_rules) > 0:
                did_update = True
                all_rules.update(sub_rules)
                break

    return all_rules

def unpack_overrides(overrides):
    if overrides is None:
        return {}

    o = {}
    for override in overrides:
        key, value = override[0].split('=')
        o[key.replace('-', ' ')] = ASTKeyword(value)

    return o

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="""bnf.py is a CLI tool and module for parsing, manipulating
        and resolving paths from BNF definitions.""",
        epilog='''Foo\n
        Bar'''
    )

    parser.add_argument('bnf_file', type=str, help='A path to a BNF file.')

    parser.add_argument('--validate', action='store_const', const=True,
        help="""Validate the BNF file. If the validation is successful there
        will be no output and the exit code will be zero.""")

    parser.add_argument('--all-rules', action='store_const', const=True,
        help='Output all BNF rules sorted by name.')

    parser.add_argument('--rule', type=str, nargs='+',
        help='One or more BNF rule names.')
    parser.add_argument('--subrules', action='store_const', const=True,
        help='Will also output any subrules of the provided rules.')

    parser.add_argument('--paths', type=str, nargs='+',
        help='Output all possible paths from one or more BNF syntaxes.')
    parser.add_argument('--override', type=str, nargs='*', action='append',
        help='Override rules when resolving paths.')
    parser.add_argument('--exclude', type=str,
        help="""Exclude paths that contain one of the keywords. Separate
        multiple keywords with a comma.""")

    args = parser.parse_args()

    exclude = []
    if args.exclude:
        exclude = args.exclude.split(',')

    raw_rules = parse_bnf_file(args.bnf_file)
    rules = analyze_rules(raw_rules)

    # --validate
    if args.validate is True:
        missing_rules = find_missing_rules(rules)
        if len(missing_rules):
            print("The following rules are missing from the grammar:\n")
            print('  ' + '\n  '.join(missing_rules))
            sys.exit(1)
        sys.exit(0)

    # --all-rules
    overrides = unpack_overrides(args.override)
    if args.all_rules:
        for rule in sorted(rules):
            print('<%s> ::=\n%s\n' % (rule, str(rules[rule]['ast'])))
        sys.exit(0)

    # When no rules are provided we print out all of them
    if args.rule is None:
        for path in args.paths:
            print('\n'.join(get_paths_for_rule(rules, str(path), overrides, exclude)))
    else:
        for r in args.rule:
            rules_to_render = set([r])
            if args.subrules:
                rules_to_render = get_subrules(rules, r)
            
            for rule in sorted(rules_to_render):
                print('<%s> ::=\n%s\n' % (rule, str(rules[rule]['ast'])))
