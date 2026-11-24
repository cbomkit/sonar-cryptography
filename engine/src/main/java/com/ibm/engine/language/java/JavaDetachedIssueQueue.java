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
package com.ibm.engine.language.java;

import com.ibm.engine.callstack.DetachedSyntaxToken;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.plugins.java.api.JavaCheck;

/**
 * Scan-scoped queue of issues raised by detached (tree-free) cross-file Java detections.
 *
 * <p>Such detections fire while sonar-java is scanning a <em>different</em> file than the one the
 * issue belongs to, so they cannot be reported through a file's {@code JavaFileScannerContext}
 * without keeping its AST alive. Instead they are queued here (no AST is retained) and saved
 * through the public sensor API by a project sensor that runs after sonar-java's {@code
 * JavaSensor}.
 */
public final class JavaDetachedIssueQueue {

    /**
     * An issue to raise on {@code inputFile} at {@code location}.
     *
     * @param rule the check that raised it; it carries the {@code @Rule} key
     */
    public record Issue(
            @Nonnull JavaCheck rule,
            @Nonnull InputFile inputFile,
            @Nonnull DetachedSyntaxToken location,
            @Nonnull String message) {}

    private static final List<Issue> ISSUES = new ArrayList<>();

    private JavaDetachedIssueQueue() {
        // static holder
    }

    static void add(@Nonnull Issue issue) {
        synchronized (ISSUES) {
            ISSUES.add(issue);
        }
    }

    /** Returns all queued issues and empties the queue. */
    @Nonnull
    public static List<Issue> drain() {
        synchronized (ISSUES) {
            final List<Issue> drained = List.copyOf(ISSUES);
            ISSUES.clear();
            return drained;
        }
    }

    /** Discards all queued issues. */
    public static void reset() {
        synchronized (ISSUES) {
            ISSUES.clear();
        }
    }
}
