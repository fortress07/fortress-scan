package com.acme.shop.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class Shell {
    private Shell() {
    }

    public static String run(String command) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", command});  // fsb-allow: FSB-CMD-003
        process.waitFor();
        return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    public static String runArgs(String... argv) throws IOException, InterruptedException {
        Process process = new ProcessBuilder(argv).start();
        process.waitFor();
        return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }
}
