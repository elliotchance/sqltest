The goal of this project is to develop a comprehensive suite of SQL tests, based
on the each of the SQL standards to be able to test to conformance of individual
SQL databases and engines.

[**View the results here**](http://htmlpreview.github.io/?https://github.com/elliotchance/sqltest/blob/master/index.html)

The [latest SQL standard](https://www.iso.org/standard/63556.html) is **not
free** and the licence does not allow all or parts of it to be published. Older
versions are either out of licence, or they don't mind, here is the
[SQL-92 standard](https://www.contrib.andrew.cmu.edu/~shadow/sql/sql1992.txt).


How It Works
============

There's a lot to explain, so here is a quick overview:

1. Extract all of the BNF from the SQL standard PDF document.
2. We use this syntax defintion with `bnf.py` to produce comprehensive tests.
3. Each of the standards features are made up of one or more of these templates
   that produce many SQL tests, *automagically*.
4. The tests are run against a database and a pretty HTML report is produced.

In a nutshell, let's look at the feature [E011-02](https://github.com/elliotchance/sqltest/blob/master/standards/2016/E/E011-02.yml). When reading
the top secret SQL standard document we come up with 3 base tests:

```yml
sql: CREATE TABLE TN ( A <approximate numeric type> )
override:
  precision: 2
---
sql: SELECT <sign> 7.8
---
sql: SELECT { <signed numeric literal> | <unsigned numeric literal> }
override:
  digit: 2
```

When running the suite these automatically expand into
[70 individual tests](https://github.com/elliotchance/sqltest/blob/master/standards/2016/E/E011-02.tests.yml)
that are executed against the actual database to produce the final report.


Progress
========

Almost all of the mandatory features of the 2016 SQL standard have had tests
written for it, but there is a lot more work to be done.


In More Detail
==============

The SQL 2016, Part 2 is a 1,732 page PDF document. The document contains many
individual definitions of syntax described in
[Backus–Naur form (BNF)](https://en.wikipedia.org/wiki/Backus–Naur_form). All of
these BNF rules are extracted from the PDF into a single file called
[bnf.txt](https://github.com/elliotchance/sqltest/blob/master/standards/2016/bnf.txt).

We can use the BNF syntax *backwards* to generate combinations of valid SQL. A
custom tool -
[bnf.py](https://github.com/elliotchance/sqltest/blob/master/bnf.py) has been
developed for this reason. It contains a few cool features but its main job is
to output SQL from the BNF file.

For example:

```bash
python bnf.py standards/2016/bnf.txt --paths 'A <comp op> { B | 5 }'
```

Produces:

```
A < 5
A < B
A <= 5
A <= B
A <> 5
A <> B
A = 5
A = B
A > 5
A > B
A >= 5
A >= B
```

This becomes especially useful when there is complex nesting of rules, we can
see the rule defintions for `<signed numeric literal>` and
`<unsigned numeric literal>` by using the command:

```bash
python bnf.py standards/2016/bnf.txt --rule 'signed numeric literal' 'unsigned numeric literal' --subrules
```

Which produces:

```bnf
<approximate numeric literal> ::=
    <mantissa> E <exponent>

<digit> ::=
    0
  | 1
  | 2
  | 3
  | 4
  | 5
  | 6
  | 7
  | 8
  | 9

<exact numeric literal> ::=
    <unsigned integer> [ <period> [ <unsigned integer> ] ]
  | <period> <unsigned integer>

<exponent> ::=
    <signed integer>

<mantissa> ::=
    <exact numeric literal>

<minus sign> ::=
    -

<period> ::=
    .

<plus sign> ::=
    +

<sign> ::=
    <plus sign>
  | <minus sign>

<signed integer> ::=
    [ <sign> ] <unsigned integer>

<signed numeric literal> ::=
    [ <sign> ] <unsigned numeric literal>

<unsigned integer> ::=
    <digit>...

<unsigned numeric literal> ::=
    <exact numeric literal>
  | <approximate numeric literal>

<approximate numeric literal> ::=
    <mantissa> E <exponent>

<digit> ::=
    0
  | 1
  | 2
  | 3
  | 4
  | 5
  | 6
  | 7
  | 8
  | 9

<exact numeric literal> ::=
    <unsigned integer> [ <period> [ <unsigned integer> ] ]
  | <period> <unsigned integer>

<exponent> ::=
    <signed integer>

<mantissa> ::=
    <exact numeric literal>

<minus sign> ::=
    -

<period> ::=
    .

<plus sign> ::=
    +

<sign> ::=
    <plus sign>
  | <minus sign>

<signed integer> ::=
    [ <sign> ] <unsigned integer>

<unsigned integer> ::=
    <digit>...

<unsigned numeric literal> ::=
    <exact numeric literal>
  | <approximate numeric literal>
```

Trying to generate a comprehansive set of tests from these rules manually would
be very difficult (and this is a very simple example). It's easy with `bnf.py`:

```bash
python bnf.py standards/2016/bnf.txt --paths 'SELECT { <signed numeric literal> | <unsigned numeric literal> }' --override 'digit=2'
```

Produces:

```
SELECT +.2
SELECT +.2E+2
SELECT +.2E-2
SELECT +.2E2
SELECT +2
SELECT +2.
SELECT +2.2
SELECT +2.2E+2
SELECT +2.2E-2
SELECT +2.2E2
SELECT +2.E+2
SELECT +2.E-2
SELECT +2.E2
SELECT +2E+2
SELECT +2E-2
SELECT +2E2
SELECT -.2
SELECT -.2E+2
SELECT -.2E-2
SELECT -.2E2
SELECT -2
SELECT -2.
SELECT -2.2
SELECT -2.2E+2
SELECT -2.2E-2
SELECT -2.2E2
SELECT -2.E+2
SELECT -2.E-2
SELECT -2.E2
SELECT -2E+2
SELECT -2E-2
SELECT -2E2
SELECT .2
SELECT .2
SELECT .2E+2
SELECT .2E+2
SELECT .2E-2
SELECT .2E-2
SELECT .2E2
SELECT .2E2
SELECT 2
SELECT 2
SELECT 2.
SELECT 2.
SELECT 2.2
SELECT 2.2
SELECT 2.2E+2
SELECT 2.2E+2
SELECT 2.2E-2
SELECT 2.2E-2
SELECT 2.2E2
SELECT 2.2E2
SELECT 2.E+2
SELECT 2.E+2
SELECT 2.E-2
SELECT 2.E-2
SELECT 2.E2
SELECT 2.E2
SELECT 2E+2
SELECT 2E+2
SELECT 2E-2
SELECT 2E-2
SELECT 2E2
SELECT 2E2
```

The `override` is important, it allows a rule (in this case `<digit>`) to have a
fixed value. Without this option we would generate *many* more cases as it would
do a combination of every number. Which is not important for our testing.

`override` also becomes critical for rules that are recurrsive to prevent it
from trying to produce an infinite amount of results.
