import sqlite3

def run_test(test):
    error = None
    try:
        conn = sqlite3.connect(':memory:')
        conn.isolation_level = None

        c = conn.cursor()
        for sql in test['sql']:
            c.execute(sql)

        # conn.commit()
        conn.close()
    except sqlite3.OperationalError as e:
        error = e

    return error
