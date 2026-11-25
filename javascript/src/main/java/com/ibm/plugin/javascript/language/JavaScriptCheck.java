/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2026 PQCA
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
package com.ibm.plugin.javascript.language;

import com.ibm.plugin.javascript.tree.JavaScriptBlockTree;
import javax.annotation.Nonnull;

/**
 * Marker interface for JavaScript/TypeScript cryptography detection checks.
 *
 * <p>sonar-javascript exposes no custom-rule API, so the sensor parses each file with ANTLR4 and
 * calls {@link #scan} directly for every block it extracts.
 */
public interface JavaScriptCheck {

    /** Invoked once per block (module body or function body) found in a source file. */
    void scan(@Nonnull JavaScriptScanContext scanContext, @Nonnull JavaScriptBlockTree blockTree);
}
