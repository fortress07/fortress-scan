package com.acme.shop.repo;

import org.springframework.stereotype.Repository;

@Repository
public class OrderRepository extends BaseRepository {
    @Override
    protected String table() {
        return "orders";
    }
}
