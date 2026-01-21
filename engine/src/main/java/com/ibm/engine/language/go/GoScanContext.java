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
package com.ibm.engine.language.go;

import com.ibm.engine.language.IScanContext;
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.CheckContext;
import org.sonar.plugins.go.api.checks.GoCheck;

/**
 * Go scan context wrapping the SonarQube Go CheckContext.
 *
 * <p>Note: In the Go API, reportIssue doesn't take a rule parameter since the rule is inferred from
 * the check that registered the handler. The rule parameter is ignored in this implementation.
 */
public record GoScanContext(@Nonnull CheckContext checkContext)
        implements IScanContext<GoCheck, Tree> {

    @Override
    public void reportIssue(
            @Nonnull GoCheck currentRule, @Nonnull Tree tree, @Nonnull String message) {
        // Go API doesn't require the rule parameter - it's inferred from the check
        this.checkContext.reportIssue(tree, message);
    }

    @Nonnull
    @Override
    public InputFile getInputFile() {
        return this.checkContext.inputFile();
    }

    @Nonnull
    @Override
    public String getFilePath() {
        return this.checkContext.inputFile().uri().getPath();
    }
}
