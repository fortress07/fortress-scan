package com.acme.shop.web;

import com.acme.shop.service.OrderService;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/orders")
public class OrderController {
    private final OrderService orders;

    public OrderController(OrderService orders) {
        this.orders = orders;
    }

    @GetMapping("/search")
    public List<Map<String, Object>> search(@RequestParam String customer) {
        return orders.findByCustomer(customer); // fsb-expect: FSB-SQL-001
    }

    @GetMapping("/{id}")
    public Map<String, Object> get(@PathVariable long id) {
        return orders.findById(id);
    }

    @GetMapping("/status")
    public List<Map<String, Object>> byStatus(@RequestParam String status) {
        return orders.findByStatus(status);
    }

    @GetMapping("/sorted")
    public List<Map<String, Object>> sorted(@RequestParam(defaultValue = "created_at") String sort) {
        return orders.listSorted(sort); // fsb-expect: FSB-SQL-001
    }
}
