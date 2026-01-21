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
package com.ibm.engine.language;

import com.ibm.engine.language.go.GoLanguageSupport;
import com.ibm.engine.language.go.GoScanContext;
import com.ibm.engine.language.java.JavaLanguageSupport;
import com.ibm.engine.language.python.PythonLanguageSupport;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;
import org.sonar.plugins.go.api.checks.GoCheck;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;

public final class LanguageSupporter {

    private LanguageSupporter() {
        // nothing
    }

    @Nonnull
    public static ILanguageSupport<
                    JavaCheck,
                    org.sonar.plugins.java.api.tree.Tree,
                    org.sonar.plugins.java.api.semantic.Symbol,
                    JavaFileScannerContext>
            javaLanguageSupporter() {
        return new JavaLanguageSupport();
    }

    @Nonnull
    public static ILanguageSupport<
                    PythonCheck,
                    org.sonar.plugins.python.api.tree.Tree,
                    org.sonar.plugins.python.api.symbols.Symbol,
                    PythonVisitorContext>
            pythonLanguageSupporter() {
        return new PythonLanguageSupport();
    }

    @Nonnull
    public static ILanguageSupport<GoCheck, Tree, Void, GoScanContext> goLanguageSupporter() {
        return new GoLanguageSupport();
    }
}
