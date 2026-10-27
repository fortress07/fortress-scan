package com.acme.shop.service;

import java.util.List;
import java.util.Map;

public interface OrderService {
    List<Map<String, Object>> findByCustomer(String customer);

    Map<String, Object> findById(long id);

    List<Map<String, Object>> findByStatus(String status);

    List<Map<String, Object>> listSorted(String column);
}
