package com.acme.orders.service;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.acme.orders.domain.Order;
import com.acme.orders.mapper.OrderMapper;

@Service
public class JdbcOrderService implements OrderService {
    private final DataSource dataSource;
    private final OrderMapper mapper;

    @Value("${orders.search-query}")
    private String searchQuery;

    @Autowired
    public JdbcOrderService(DataSource dataSource, OrderMapper mapper) {
        this.dataSource = dataSource;
        this.mapper = mapper;
    }

    @Override
    public List<Order> search(String term) {
        return runQuery(searchQuery + "code LIKE '%" + term + "%'");
    }

    @Override
    public List<Order> sorted(String column) {
        return mapper.findSorted(column);
    }

    @Override
    public Order byCode(String code) {
        return mapper.findByCode(code);
    }

    private List<Order> runQuery(String sql) {
        List<Order> found = new ArrayList<>();
        try (Connection connection = dataSource.getConnection();
                Statement statement = connection.createStatement();
                ResultSet rows = statement.executeQuery(sql)) {
            while (rows.next()) {
                Order order = new Order();
                order.setCode(rows.getString("code"));
                order.setTotal(rows.getString("total"));
                found.add(order);
            }
        } catch (Exception failed) {
            throw new IllegalStateException(failed);
        }
        return found;
    }
}
