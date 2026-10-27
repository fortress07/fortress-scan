package com.acme.shop.repo;

import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

public abstract class BaseRepository {
    @Autowired
    protected JdbcTemplate jdbc;

    protected abstract String table();

    public List<Map<String, Object>> select(String where) {
        return jdbc.queryForList("SELECT * FROM " + table() + " WHERE " + where);  // fsb-allow: FSB-SQL-002
    }

    public Map<String, Object> selectOne(String where) {
        return jdbc.queryForMap("SELECT * FROM " + table() + " WHERE " + where);  // fsb-allow: FSB-SQL-002
    }

    public List<Map<String, Object>> selectOrdered(String column) {
        return jdbc.queryForList("SELECT * FROM " + table() + " ORDER BY " + column);  // fsb-allow: FSB-SQL-002
    }
}
