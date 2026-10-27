package com.acme.orders.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import com.acme.orders.domain.Order;

public interface OrderMapper {
    Order findByCode(@Param("code") String code);

    List<Order> findSorted(@Param("column") String column);

    @Select("SELECT id, code, total FROM orders WHERE status = '${status}'")
    List<Order> findByStatus(@Param("status") String status);
}
