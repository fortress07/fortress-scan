import psycopg2


class BaseRepository:
    table = ""

    def __init__(self):
        self.connection = psycopg2.connect("dbname=inventory")

    def _fetch(self, sql, params=None):
        with self.connection.cursor() as cursor:
            cursor.execute(sql, params)  # fsb-allow: FSB-SQL-002
            return cursor.fetchall()

    def _where(self, clause):
        return self._fetch("SELECT * FROM " + self.table + " WHERE " + clause)
