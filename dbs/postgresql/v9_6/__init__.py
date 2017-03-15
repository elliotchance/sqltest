import psycopg2

def run_test(test):
    error = None
    try:
        conn = psycopg2.connect("host='localhost' dbname='postgres' user='postgres' password=''")

        c = conn.cursor()
        for sql in test['sql']:
            c.execute(sql)

        conn.close()
    except psycopg2.Error as e:
        error = e

    return error
