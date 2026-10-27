package com.acme.orders.service;

import java.util.List;

import com.acme.orders.domain.Order;

public interface OrderService {
    List<Order> search(String term);

    List<Order> sorted(String column);

    Order byCode(String code);
}
