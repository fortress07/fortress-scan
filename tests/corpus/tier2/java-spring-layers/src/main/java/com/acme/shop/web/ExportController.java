package com.acme.shop.web;

import com.acme.shop.dto.ExportRequest;
import com.acme.shop.service.ExportService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExportController {
    @Autowired
    private ExportService exportService;

    @PostMapping("/export")
    public String export(@RequestBody ExportRequest request) throws Exception {
        return exportService.export(request.getFileName()); // fsb-expect: FSB-CMD-001
    }

    @PostMapping("/export/archive")
    public String archive(@RequestBody ExportRequest request) throws Exception {
        return exportService.archive(request.getFileName());
    }
}
