package com.acme.orders.web;

import java.io.IOException;
import java.util.Set;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

import com.acme.orders.service.ExportService;
import com.acme.orders.service.OrderService;

@Controller
public class OrderController {
    private static final Set<String> COLUMNS = Set.of("code", "total", "created_at");

    private final OrderService orders;
    private final ExportService exports;

    public OrderController(OrderService orders, ExportService exports) {
        this.orders = orders;
        this.exports = exports;
    }

    @GetMapping("/orders")
    public String search(@RequestParam String term, Model model) {
        model.addAttribute("orders", orders.search(term));  // fsb-expect: FSB-SQL-001
        return "list";
    }

    @GetMapping("/orders/sorted")
    public String sorted(@RequestParam String column, Model model) {
        model.addAttribute("orders", orders.sorted(column));  // fsb-expect: FSB-SQL-001
        return "list";
    }

    @GetMapping("/orders/sorted-safe")
    public String sortedSafe(@RequestParam String column, Model model) {
        if (!COLUMNS.contains(column)) {
            throw new IllegalArgumentException("cột không hợp lệ");
        }
        model.addAttribute("orders", orders.sorted(column));
        return "list";
    }

    @GetMapping("/orders/{code}")
    public String view(@PathVariable String code, @RequestParam String note, Model model) {
        model.addAttribute("order", orders.byCode(code));
        model.addAttribute("note", note);  // fsb-expect: FSB-XSS-001
        return "order";
    }

    @GetMapping("/orders/note-safe")
    public String noteSafe(@RequestParam String note, Model model) {
        model.addAttribute("note", note);
        return "safe";
    }

    @GetMapping("/orders/archive")
    public byte[] archive(@RequestParam String name) throws IOException {
        return exports.archived(name);  // fsb-expect: FSB-PATH-001
    }
}
