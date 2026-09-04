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
package com.ibm.plugin.bridge;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.plugin.bridge.model.EslintAnalysisRequest;
import com.ibm.plugin.bridge.model.EslintAnalysisResult;
import com.ibm.plugin.bridge.model.EslintInputFile;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import javax.annotation.Nonnull;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.ExecuteException;
import org.apache.commons.exec.PumpStreamHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Executes the bundled Node.js ESLint runner and returns parsed analysis results. */
public final class ESLintExecutor {

    @Nonnull private static final Logger LOG = LoggerFactory.getLogger(ESLintExecutor.class);

    @Nonnull private static final ObjectMapper MAPPER = new ObjectMapper();

    @Nonnull private static final String NODE_RESOURCE_ROOT = "/node";

    @Nonnull private final Path nodeHome;
    @Nonnull private final Path nodeExecutable;
    @Nonnull private final Path runnerScript;

    public ESLintExecutor(@Nonnull Path nodeHome) {
        this.nodeHome = nodeHome;
        this.nodeExecutable = nodeHome.resolve("node").resolve("node");
        this.runnerScript = nodeHome.resolve("eslint-runner.js");
    }

    @Nonnull
    public static ESLintExecutor fromClasspathResources() throws IOException {
        return new ESLintExecutor(resolveNodeHome());
    }

    @Nonnull
    public EslintAnalysisResult analyze(@Nonnull List<EslintInputFile> files) throws IOException {
        EslintAnalysisRequest request = new EslintAnalysisRequest(files);
        String payload = MAPPER.writeValueAsString(request);

        CommandLine commandLine = new CommandLine(nodeExecutable.toString());
        commandLine.addArgument(runnerScript.toString(), false);

        DefaultExecutor executor = new DefaultExecutor();
        executor.setWorkingDirectory(nodeHome.toFile());
        executor.setExitValues(new int[] {0});

        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        ByteArrayInputStream stdin =
                new ByteArrayInputStream(payload.getBytes(StandardCharsets.UTF_8));
        executor.setStreamHandler(new PumpStreamHandler(stdout, stderr, stdin));

        try {
            executor.execute(commandLine);
        } catch (ExecuteException e) {
            LOG.warn("ESLint runner failed: {}", stderr.toString(StandardCharsets.UTF_8));
            throw new IOException("ESLint runner failed with exit code " + e.getExitValue(), e);
        }

        String output = stdout.toString(StandardCharsets.UTF_8);
        return ESLintResultParser.parseJson(output);
    }

    @Nonnull
    private static Path resolveNodeHome() throws IOException {
        URL resourceUrl = ESLintExecutor.class.getResource(NODE_RESOURCE_ROOT);
        if (resourceUrl == null) {
            throw new IOException("Missing bundled Node resources at " + NODE_RESOURCE_ROOT);
        }
        if ("file".equals(resourceUrl.getProtocol())) {
            try {
                return Path.of(resourceUrl.toURI());
            } catch (java.net.URISyntaxException e) {
                throw new IOException("Invalid node resource URI", e);
            }
        }
        return extractNodeResourcesFromJar(resourceUrl);
    }

    @Nonnull
    private static Path extractNodeResourcesFromJar(@Nonnull URL resourceUrl) throws IOException {
        Path tempDir = Files.createTempDirectory("sonar-crypto-node-");
        tempDir.toFile().deleteOnExit();

        if ("jar".equals(resourceUrl.getProtocol())) {
            JarURLConnection connection = (JarURLConnection) resourceUrl.openConnection();
            try (JarFile jarFile = connection.getJarFile()) {
                String prefix = connection.getEntryName();
                if (prefix == null) {
                    prefix = "node";
                }
                if (!prefix.endsWith("/")) {
                    prefix = prefix + "/";
                }
                Enumeration<JarEntry> entries = jarFile.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    if (!entry.getName().startsWith(prefix) || entry.isDirectory()) {
                        continue;
                    }
                    String relativePath = entry.getName().substring(prefix.length());
                    Path target = tempDir.resolve(relativePath);
                    Files.createDirectories(target.getParent());
                    try (InputStream inputStream = jarFile.getInputStream(entry)) {
                        Files.copy(inputStream, target, StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            }
        } else {
            try {
                copyResourceTree(resourceUrl.toURI(), tempDir);
            } catch (java.net.URISyntaxException e) {
                throw new IOException("Invalid node resource URI", e);
            }
        }

        Path nodeBinary = tempDir.resolve("node").resolve("node");
        if (Files.exists(nodeBinary)) {
            nodeBinary.toFile().setExecutable(true);
        }
        return tempDir;
    }

    private static void copyResourceTree(@Nonnull URI sourceUri, @Nonnull Path targetDir)
            throws IOException {
        Path sourcePath = Path.of(sourceUri);
        Files.walkFileTree(
                sourcePath,
                new SimpleFileVisitor<>() {
                    @Override
                    @Nonnull
                    public FileVisitResult preVisitDirectory(
                            @Nonnull Path dir, @Nonnull BasicFileAttributes attrs)
                            throws IOException {
                        Path relative = sourcePath.relativize(dir);
                        Files.createDirectories(targetDir.resolve(relative));
                        return FileVisitResult.CONTINUE;
                    }

                    @Override
                    @Nonnull
                    public FileVisitResult visitFile(
                            @Nonnull Path file, @Nonnull BasicFileAttributes attrs)
                            throws IOException {
                        Path relative = sourcePath.relativize(file);
                        Files.copy(
                                file,
                                targetDir.resolve(relative),
                                StandardCopyOption.REPLACE_EXISTING);
                        return FileVisitResult.CONTINUE;
                    }
                });
    }
}
