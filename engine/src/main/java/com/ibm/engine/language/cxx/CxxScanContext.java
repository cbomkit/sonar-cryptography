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

import com.ibm.engine.language.IScanContext;
import com.sonar.cxx.sslr.api.AstNode;
import com.sonar.cxx.sslr.api.Grammar;
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.cxx.squidbridge.SquidAstVisitorContext;
import org.sonar.cxx.squidbridge.checks.SquidCheck;

public record CxxScanContext(@Nonnull SquidAstVisitorContext<? extends Grammar> cxxVisitorContext)
        implements IScanContext<SquidCheck<?>, AstNode> {

    @Override
    public void reportIssue(
            @Nonnull SquidCheck<?> currentRule, @Nonnull AstNode tree, @Nonnull String message) {
        currentRule.addIssue(tree, message);
    }

    @Nonnull
    @Override
    public InputFile getInputFile() {
        return this.cxxVisitorContext.getInputFile();
    }

    @Nonnull
    @Override
    public String getFilePath() {
        return this.cxxVisitorContext.getInputFile().uri().getPath();
    }
}
