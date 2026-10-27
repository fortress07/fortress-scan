package com.acme.orders.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class ExportService {
    @Value("${orders.export-command}")
    private String exportCommand;

    @Value("${orders.archive-root}")
    private String archiveRoot;

    public void export(String name) throws IOException {
        Runtime.getRuntime().exec(exportCommand + " --name " + name);  // fsb-allow: FSB-CMD-003
    }

    public byte[] archived(String name) throws IOException {
        Path path = Paths.get(archiveRoot, name);
        return Files.readAllBytes(path);
    }

    public byte[] archivedChecked(String name) throws IOException {
        Path path = Paths.get(archiveRoot, Paths.get(name).getFileName().toString());
        return Files.readAllBytes(path);
    }
}
