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
package com.ibm.plugin.translation.translator;

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.javascript.api.CallExpressionTree;
import com.ibm.plugin.javascript.api.HasLocation;
import com.ibm.plugin.javascript.api.JavaScriptCheck;
import com.ibm.plugin.javascript.api.JavaScriptSymbol;
import com.ibm.plugin.javascript.api.MemberExpressionTree;
import com.ibm.plugin.javascript.api.Tree;
import com.ibm.plugin.javascript.language.JavaScriptScanContext;
import com.ibm.plugin.translation.translator.contexts.JavaScriptCipherContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaScriptDigestContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaScriptKeyAgreementContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaScriptKeyContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaScriptKeyDerivationContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaScriptMacContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaScriptPRNGContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaScriptPrivateKeyContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaScriptPublicKeyContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaScriptSecretKeyContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaScriptProtocolContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaScriptSignatureContextTranslator;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JavaScriptTranslator
        extends ITranslator<JavaScriptCheck, Tree, JavaScriptSymbol, JavaScriptScanContext> {

    @Nonnull
    @Override
    public Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionValueContext,
            @Nonnull String filePath) {
        DetectionLocation detectionLocation =
                getDetectionContextFrom(value.getLocation(), bundleIdentifier, filePath);
        if (detectionLocation == null) {
            return Optional.empty();
        }

        if (detectionValueContext.is(CipherContext.class)) {
            return new JavaScriptCipherContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        if (detectionValueContext.is(DigestContext.class)) {
            return new JavaScriptDigestContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        if (detectionValueContext.is(MacContext.class)) {
            return new JavaScriptMacContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        if (detectionValueContext.is(PRNGContext.class)) {
            return new JavaScriptPRNGContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        if (detectionValueContext.is(KeyDerivationFunctionContext.class)) {
            return new JavaScriptKeyDerivationContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        if (detectionValueContext.is(KeyAgreementContext.class)) {
            return new JavaScriptKeyAgreementContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        if (detectionValueContext.is(SecretKeyContext.class)) {
            return new JavaScriptSecretKeyContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        if (detectionValueContext.is(PublicKeyContext.class)) {
            return new JavaScriptPublicKeyContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        if (detectionValueContext.is(PrivateKeyContext.class)) {
            return new JavaScriptPrivateKeyContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        if (detectionValueContext.is(KeyContext.class)) {
            return new JavaScriptKeyContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        if (detectionValueContext.is(SignatureContext.class)) {
            return new JavaScriptSignatureContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        if (detectionValueContext.is(ProtocolContext.class)) {
            return new JavaScriptProtocolContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }

        return Optional.empty();
    }

    @Nullable @Override
    protected DetectionLocation getDetectionContextFrom(
            @Nonnull Tree location, @Nonnull IBundle bundle, @Nonnull String filePath) {
        if (!(location instanceof HasLocation hasLocation)) {
            return null;
        }

        List<String> keywords = List.of();
        if (location instanceof CallExpressionTree call) {
            keywords = List.of(call.methodName());
        } else if (location instanceof MemberExpressionTree member) {
            keywords = List.of(member.propertyName());
        }

        return new DetectionLocation(
                filePath,
                hasLocation.location().line(),
                hasLocation.location().column(),
                keywords,
                bundle);
    }
}
