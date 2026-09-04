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
package com.ibm.plugin;

import com.ibm.plugin.javascript.api.JavaScriptCheck;
import com.ibm.plugin.rules.JavaScriptInventoryRule;
import com.ibm.plugin.rules.JavaScriptNoMD5UseRule;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;

public final class JavaScriptRuleList {

    private JavaScriptRuleList() {}

    @Nonnull
    public static List<Class<?>> getChecks() {
        List<Class<? extends JavaScriptCheck>> checks = new ArrayList<>();
        checks.addAll(getJavaScriptChecks());
        checks.addAll(getJavaScriptTestChecks());
        return Collections.unmodifiableList(checks);
    }

    @Nonnull
    public static List<Class<? extends JavaScriptCheck>> getJavaScriptChecks() {
        return List.of(JavaScriptInventoryRule.class, JavaScriptNoMD5UseRule.class);
    }

    @Nonnull
    public static List<Class<? extends JavaScriptCheck>> getJavaScriptTestChecks() {
        return List.of();
    }
}
