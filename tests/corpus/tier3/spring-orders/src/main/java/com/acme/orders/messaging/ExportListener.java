package com.acme.orders.messaging;

import java.io.IOException;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import com.acme.orders.service.ExportService;

@Component
public class ExportListener {
    private final ExportService exports;

    public ExportListener(ExportService exports) {
        this.exports = exports;
    }

    @KafkaListener(topics = "order-export")
    public void onExport(String payload) throws IOException {
        exports.export(payload);  // fsb-expect: FSB-CMD-001
    }
}
