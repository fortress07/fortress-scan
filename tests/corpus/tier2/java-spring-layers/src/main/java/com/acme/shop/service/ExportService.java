package com.acme.shop.service;

import com.acme.shop.util.Shell;
import org.springframework.stereotype.Service;

@Service
public class ExportService {
    private static final String EXPORT_DIR = "/var/exports/";

    public String export(String fileName) throws Exception {
        return Shell.run("pg_dump shop -f " + EXPORT_DIR + fileName);
    }

    public String archive(String fileName) throws Exception {
        return Shell.runArgs("tar", "czf", EXPORT_DIR + "archive.tgz", EXPORT_DIR + fileName);
    }
}
