/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sonar.go.testing;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.go.converter.Command;
import org.sonar.go.converter.PlatformInfo;
import org.sonar.go.converter.SystemPlatformInfo;
import org.sonar.plugins.go.api.ParseException;

/**
 * This file is adapted from SonarSource sonar-go project: <a
 * href="https://github.com/SonarSource/sonar-go/blob/master/sonar-go-commons/src/main/java/org/sonar/go/converter/DefaultCommand.java">...</a>
 *
 * <p>Modifications have been made to work with this project's testing infrastructure.
 *
 * <p>A {@link Command} implementation that uses an existing sonar-go-to-slang binary without
 * extracting it from the JAR. This allows using a custom-built binary for testing.
 *
 * <p>The binary must already exist in the converter directory with the appropriate
 * platform-specific name (e.g., sonar-go-to-slang-darwin-arm64).
 */
public class GoParseWithExistingBinaryCommand implements Command {
    private static final Logger LOG =
            LoggerFactory.getLogger(GoParseWithExistingBinaryCommand.class);

    private static final long PROCESS_TIMEOUT_MS = 5_000;
    private static final int COPY_BUFFER_SIZE = 8192;
    private static final int FILENAME_AND_CONTENT_LENGTH = 8;

    protected final List<String> command;
    private final int moduleNameIndex;

    public GoParseWithExistingBinaryCommand(File workDir, String... extraArgs) {
        this(workDir, new SystemPlatformInfo(), extraArgs);
    }

    public GoParseWithExistingBinaryCommand(
            File workDir, PlatformInfo platformInfo, String... arguments) {
        command = new ArrayList<>();
        var executable = findExistingBinary(workDir);
        command.add(executable);
        command.addAll(
                Arrays.asList(
                        mergeArgs(
                                arguments,
                                "-module_name",
                                "moduleNamePlaceholder",
                                "-gc_export_data_dir",
                                new File(workDir, "go").getAbsolutePath())));
        moduleNameIndex = command.indexOf("moduleNamePlaceholder");
    }

    public void debugTypeCheck() {
        command.add("-debug_type_check");
    }

    private static String[] mergeArgs(String[] args, String... extraArgs) {
        if (args.length == 0) {
            return extraArgs;
        }
        var merged = new String[args.length + extraArgs.length];
        System.arraycopy(args, 0, merged, 0, args.length);
        System.arraycopy(extraArgs, 0, merged, args.length, extraArgs.length);
        return merged;
    }

    public String executeGoParseCommand(Map<String, String> filenameToContentMap, String moduleName)
            throws IOException, InterruptedException {
        command.set(moduleNameIndex, moduleName);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Executing Go parse data command: {}", String.join(" ", command));
        }
        return executeCommand(filenameToContentMap);
    }

    private String findExistingBinary(File converterDir) {
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch").toLowerCase(Locale.ROOT);

        String osName;
        if (os.contains("mac") || os.contains("darwin")) {
            osName = "darwin";
        } else if (os.contains("win")) {
            osName = "windows";
        } else {
            osName = "linux";
        }

        String archName;
        if (arch.contains("aarch64") || arch.contains("arm64")) {
            archName = "arm64";
        } else {
            archName = "amd64";
        }

        String binaryName = "sonar-go-to-slang-" + osName + "-" + archName;
        if ("windows".equals(osName)) {
            binaryName += ".exe";
        }

        File binary = new File(converterDir, binaryName);
        if (!binary.exists()) {
            throw new IllegalStateException(
                    "Binary not found: "
                            + binary.getAbsolutePath()
                            + ". Place your custom binary there before running tests.");
        }
        if (!binary.canExecute()) {
            throw new IllegalStateException(
                    "Binary is not executable: "
                            + binary.getAbsolutePath()
                            + ". Run: chmod +x "
                            + binary.getAbsolutePath());
        }

        return binary.getAbsolutePath();
    }

    @Override
    public List<String> getCommand() {
        return command;
    }

    @Override
    public String executeCommand(Map<String, String> filenameToContentMap)
            throws IOException, InterruptedException {
        var byteBuffers = convertToBytesArray(filenameToContentMap);

        var processBuilder = new ProcessBuilder(getCommand());
        var executor = Executors.newSingleThreadExecutor();

        var process = processBuilder.start();
        try {
            // Consume error stream asynchronously
            executor.submit(
                    () -> {
                        try (var reader =
                                new BufferedReader(
                                        new InputStreamReader(process.getErrorStream(), UTF_8))) {
                            String line;
                            while ((line = reader.readLine()) != null) {
                                LOG.debug(line);
                            }
                        } catch (IOException e) {
                            LOG.debug("Error reading process error stream", e);
                        }
                    });
            try (var out = process.getOutputStream()) {
                for (ByteBuffer byteBuffer : byteBuffers) {
                    out.write(byteBuffer.array());
                }
            }
            String output;
            try (var in = process.getInputStream()) {
                output = readAsString(in);
            }
            boolean exited = process.waitFor(PROCESS_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            if (exited && process.exitValue() != 0) {
                throw new ParseException(
                        "Go executable returned non-zero exit value: " + process.exitValue());
            }
            if (process.isAlive()) {
                process.destroyForcibly();
                throw new ParseException(
                        "Go executable took too long. External process killed forcibly");
            }
            return output;
        } finally {
            executor.shutdown();
        }
    }

    private static List<ByteBuffer> convertToBytesArray(Map<String, String> filenameToContentMap) {
        List<ByteBuffer> buffers = new ArrayList<>();
        for (Map.Entry<String, String> filenameToContent : filenameToContentMap.entrySet()) {
            var filenameBytes = filenameToContent.getKey().getBytes(UTF_8);
            var contentBytes = filenameToContent.getValue().getBytes(UTF_8);
            int capacity = filenameBytes.length + contentBytes.length + FILENAME_AND_CONTENT_LENGTH;
            var byteBuffer =
                    ByteBuffer.allocate(capacity)
                            .order(ByteOrder.LITTLE_ENDIAN)
                            .putInt(filenameBytes.length)
                            .put(filenameBytes)
                            .putInt(contentBytes.length)
                            .put(contentBytes);
            buffers.add(byteBuffer);
        }
        return buffers;
    }

    private static String readAsString(InputStream in) throws IOException {
        var outputStream = new ByteArrayOutputStream();
        copy(in, outputStream);
        return outputStream.toString(UTF_8);
    }

    public static void copy(InputStream in, OutputStream out) throws IOException {
        var buffer = new byte[COPY_BUFFER_SIZE];
        int read;
        while ((read = in.read(buffer)) >= 0) {
            out.write(buffer, 0, read);
        }
    }
}
