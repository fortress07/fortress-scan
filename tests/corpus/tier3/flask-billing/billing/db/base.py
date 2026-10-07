import psycopg2

from .. import config


class BaseRepository:
    def __init__(self):
        self.connection = psycopg2.connect("dbname=billing")
        self.list_query = config.SEARCH_QUERY

    def _fetch(self, sql, params=None):
        with self.connection.cursor() as cursor:
            cursor.execute(sql, params)  # fsb-allow: FSB-SQL-002
            return cursor.fetchall()

    def _where(self, clause):
        return self._fetch(self.list_query + clause)
