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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.go.converter.InitializationException;
import org.sonar.go.converter.PlatformInfo;
import org.sonar.go.converter.SystemPlatformInfo;
import org.sonar.go.persistence.JsonTree;
import org.sonar.plugins.go.api.ASTConverter;
import org.sonar.plugins.go.api.ParseException;
import org.sonar.plugins.go.api.TreeOrError;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

public class GoConverter implements ASTConverter {
    private static final Logger LOG = LoggerFactory.getLogger(GoConverter.class);
    public static final long MAX_SUPPORTED_SOURCE_FILE_SIZE = 1_500_000L;
    private final GoParseWithExistingBinaryCommand command;
    private final AtomicBoolean isInitialized = new AtomicBoolean(false);

    public GoConverter(File workDir) {
        this(workDir, new SystemPlatformInfo());
    }

    public GoConverter(File workDir, PlatformInfo platformInfo) {
        GoParseWithExistingBinaryCommand commandOrNull;
        try {
            commandOrNull = new GoParseWithExistingBinaryCommand(workDir, platformInfo);
            isInitialized.set(true);
        } catch (InitializationException e) {
            LOG.warn("Go converter initialization failed: {}", e.getMessage());
            commandOrNull = null;
        }
        this.command = commandOrNull;
    }

    // Visible for testing
    public GoConverter(GoParseWithExistingBinaryCommand command) {
        this.command = command;
        this.isInitialized.set(true);
    }

    @Override
    public Map<String, TreeOrError> parse(Map<String, String> filenameToContentMap, @Nonnull String moduleName) {
        Map<String, TreeOrError> result = new HashMap<>(filenameToContentMap.size());
        Map<String, String> filesToParse = new HashMap<>();
        for (Map.Entry<String, String> entry : filenameToContentMap.entrySet()) {
            String filename = entry.getKey();
            String content = entry.getValue();
            if (content.length() > MAX_SUPPORTED_SOURCE_FILE_SIZE) {
                result.put(filename, TreeOrError.of("The file size is too big and should be excluded," +
                        " its size is " + content.length() + " (maximum allowed is " + MAX_SUPPORTED_SOURCE_FILE_SIZE + " bytes)"));
            } else {
                filesToParse.put(filename, content);
            }
        }
        try {
            var json = command.executeGoParseCommand(filesToParse, moduleName);
            result.putAll(JsonTree.fromJson(json));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ParseException("Go executable interrupted: " + e.getMessage(), null, e);
        } catch (IOException e) {
            throw new ParseException(e.getMessage(), null, e);
        }
        return result;
    }

    @Override
    public void debugTypeCheck() {
        command.debugTypeCheck();
    }

    @Override
    public boolean isInitialized() {
        return isInitialized.get();
    }
}
