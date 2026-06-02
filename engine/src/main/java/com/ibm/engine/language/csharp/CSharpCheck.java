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
package com.ibm.engine.language.csharp;

import com.ibm.engine.language.csharp.tree.CSharpBlockTree;
import javax.annotation.Nonnull;

/**
 * Marker interface for C# cryptography detection checks.
 *
 * <p>Since sonar-csharp exposes no custom rule registration API (unlike Java's CheckRegistrar or
 * Python's PythonCustomRuleRepository), {@link CryptoCSharpSensor} calls {@link #scan} directly for
 * every method body it encounters during ANTLR4-based parsing.
 */
public interface CSharpCheck {

    /**
     * Invoked once per method body found in a C# source file.
     *
     * @param scanContext the current scan context (input file, sensor context, repository key)
     * @param blockTree the method body to analyse
     */
    void scan(@Nonnull CSharpScanContext scanContext, @Nonnull CSharpBlockTree blockTree);
}
