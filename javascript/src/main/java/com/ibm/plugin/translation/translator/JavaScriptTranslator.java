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
package com.ibm.plugin.translation.translator;

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.javascript.language.JavaScriptCheck;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.javascript.language.JavaScriptSymbol;
import com.ibm.plugin.javascript.tree.JavaScriptCallTree;
import com.ibm.plugin.javascript.tree.JavaScriptTree;
import com.ibm.plugin.translation.translator.contexts.JavaScriptDigestContextTranslator;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/** Translator for JavaScript/TypeScript detections. Dispatches to context translators. */
public class JavaScriptTranslator
        extends ITranslator<
                JavaScriptCheck, JavaScriptTree, JavaScriptSymbol, JavaScriptScanContext> {

    @Nonnull
    @Override
    public Optional<INode> translate(
            @Nonnull final IBundle bundleIdentifier,
            @Nonnull final IValue<JavaScriptTree> value,
            @Nonnull final DetectionContext detectionValueContext,
            @Nonnull final String filePath) {
        DetectionLocation detectionLocation =
                getDetectionContextFrom(value.getLocation(), bundleIdentifier, filePath);
        if (detectionLocation == null) {
            return Optional.empty();
        }
        if (detectionValueContext.is(DigestContext.class)) {
            return new JavaScriptDigestContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        return Optional.empty();
    }

    @Nullable @Override
    protected DetectionLocation getDetectionContextFrom(
            @Nonnull JavaScriptTree location, @Nonnull IBundle bundle, @Nonnull String filePath) {
        List<String> keywords =
                location instanceof JavaScriptCallTree call
                        ? List.of(call.getMethodName())
                        : List.of();
        return new DetectionLocation(
                filePath, location.getLine(), location.getColumn(), keywords, bundle);
    }
}
