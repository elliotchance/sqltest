import mysql.connector

def run_test(test):
    error = None
    try:
        conn = mysql.connector.connect(user='root', password='',
                              host='localhost',
                              database='test')
        #conn.isolation_level = None

        c = conn.cursor()
        for sql in test['sql']:
            c.execute(sql)

        conn.close()
    except mysql.connector.Error as e:
        error = e

    return error
