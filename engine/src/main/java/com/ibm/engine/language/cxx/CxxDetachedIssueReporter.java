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
package com.ibm.engine.language.cxx;

import com.ibm.engine.callstack.IDetachedIssueReporter;
import com.sonar.cxx.sslr.api.AstNode;
import javax.annotation.Nonnull;
import org.sonar.cxx.squidbridge.api.SourceFile;
import org.sonar.cxx.squidbridge.checks.SquidCheck;
import org.sonar.cxx.utils.CxxReportIssue;
import org.sonar.cxx.visitors.MultiLocatitionSquidCheck;

/**
 * Raises a SonarQube issue for a detached (tree-free) cross-file detection by queuing a {@link
 * CxxReportIssue} onto the originating file's own {@link SourceFile} data bag, via {@link
 * MultiLocatitionSquidCheck#addMultiLocationViolation}. {@code CxxSquidSensor} drains every file's
 * data bag into real SonarQube issues, via {@code scanner.getIndex().search(...)}, only after the
 * whole batch has finished — so a {@link SourceFile} captured at record time (while that file is
 * still being visited) remains a valid target for {@link #report} regardless of which file is being
 * visited when the cross-file hook actually fires.
 *
 * <p>The queued {@link CxxReportIssue} carries the raising check's {@code Class}, so {@code
 * CxxSquidSensor} resolves the issue to that check's own registered rule repository (not
 * sonar-cxx's built-in one) — see {@code CxxChecks#ruleKeyForClass}.
 */
public final class CxxDetachedIssueReporter
        implements IDetachedIssueReporter<SquidCheck<?>, AstNode> {

    @Nonnull private final SourceFile sourceFile;
    @Nonnull private final String filePath;

    private CxxDetachedIssueReporter(@Nonnull SourceFile sourceFile, @Nonnull String filePath) {
        this.sourceFile = sourceFile;
        this.filePath = filePath;
    }

    @Nonnull
    static CxxDetachedIssueReporter create(
            @Nonnull SourceFile sourceFile, @Nonnull String filePath) {
        return new CxxDetachedIssueReporter(sourceFile, filePath);
    }

    @Override
    public void report(
            @Nonnull SquidCheck<?> rule, @Nonnull AstNode location, @Nonnull String message) {
        final String ruleId = ruleKeyOf(rule);
        final String line = String.valueOf(location.getTokenLine());
        final CxxReportIssue issue =
                new CxxReportIssue(ruleId, rule.getClass(), filePath, line, null, message);
        MultiLocatitionSquidCheck.addMultiLocationViolation(sourceFile, issue);
    }

    /**
     * The rule id stamped onto the {@link CxxReportIssue}. {@code CxxSquidSensor} resolves the real
     * {@code RuleKey} via the check's {@code Class} ({@code CxxChecks#ruleKeyForClass}), so this
     * value is a diagnostic label only (used in its fallback path / {@code toString}), not the
     * source of truth for which repository the issue belongs to.
     */
    @Nonnull
    private static String ruleKeyOf(@Nonnull SquidCheck<?> rule) {
        final org.sonar.check.Rule ruleAnnotation =
                rule.getClass().getAnnotation(org.sonar.check.Rule.class);
        return ruleAnnotation != null ? ruleAnnotation.key() : rule.getClass().getSimpleName();
    }
}
