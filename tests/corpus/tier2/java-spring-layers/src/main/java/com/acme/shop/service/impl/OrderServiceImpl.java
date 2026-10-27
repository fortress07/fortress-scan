package com.acme.shop.service.impl;

import com.acme.shop.repo.OrderRepository;
import com.acme.shop.service.OrderService;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Service;

@Service
public class OrderServiceImpl implements OrderService {
    private static final Set<String> STATUSES = Set.of("NEW", "PAID", "SHIPPED");
    private final OrderRepository repository;

    public OrderServiceImpl(OrderRepository repository) {
        this.repository = repository;
    }

    @Override
    public List<Map<String, Object>> findByCustomer(String customer) {
        return repository.select("customer_name = '" + customer + "'");
    }

    @Override
    public Map<String, Object> findById(long id) {
        return repository.selectOne("id = " + id);
    }

    @Override
    public List<Map<String, Object>> findByStatus(String status) {
        if (!STATUSES.contains(status)) {
            throw new IllegalArgumentException("unknown status");
        }
        return repository.select("status = '" + status + "'");
    }

    @Override
    public List<Map<String, Object>> listSorted(String column) {
        return repository.selectOrdered(column);
    }
}
