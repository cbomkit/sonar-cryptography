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

import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpMethodInvocationTree;
import com.ibm.engine.language.csharp.tree.CSharpObjectCreationTree;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.IDetectionContext;
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
import com.ibm.plugin.translation.translator.contexts.CSharpCipherContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CSharpDigestContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CSharpKeyContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CSharpMacContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CSharpPRNGContextTranslator;
import com.ibm.plugin.translation.translator.contexts.CSharpSignatureContextTranslator;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/** Translator for C# cryptographic detections. Dispatches to context-specific translators. */
public class CSharpTranslator
        extends ITranslator<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> {

    public CSharpTranslator() {
        // nothing
    }

    @Nonnull
    @Override
    public Optional<INode> translate(
            @Nonnull final IBundle bundleIdentifier,
            @Nonnull final IValue<CSharpTree> value,
            @Nonnull final IDetectionContext detectionValueContext,
            @Nonnull final String filePath) {
        DetectionLocation detectionLocation =
                getDetectionContextFrom(value.getLocation(), bundleIdentifier, filePath);
        if (detectionLocation == null) {
            return Optional.empty();
        }

        if (detectionValueContext.is(CipherContext.class)) {
            return new CSharpCipherContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }

        if (detectionValueContext.is(DigestContext.class)) {
            return new CSharpDigestContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }

        if (detectionValueContext.is(MacContext.class)) {
            return new CSharpMacContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }

        if (detectionValueContext.is(KeyContext.class)) {
            return new CSharpKeyContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }

        if (detectionValueContext.is(SignatureContext.class)) {
            return new CSharpSignatureContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }

        if (detectionValueContext.is(PRNGContext.class)) {
            return new CSharpPRNGContextTranslator()
                    .translate(bundleIdentifier, value, detectionValueContext, detectionLocation);
        }

        if (detectionValueContext.is(ProtocolContext.class)) {
            return Optional.empty();
        }

        if (detectionValueContext.is(KeyDerivationFunctionContext.class)) {
            // No C# rule currently builds a KeyDerivationFunctionContext: unlike the Python
            // module (see PycaKDF/PycaKeyDerivationContextTranslator), every KDF rule in this
            // module (DotNetKeyDerivation, DotNetRfc2898DeriveBytes; also mirrored by the Java
            // BouncyCastle rules in BcDerivationFunction) reuses the generic KeyContext with a
            // "kind" discriminator (e.g. "KDF_HKDF", "KDF_SP800108") instead, dispatched in
            // CSharpKeyContextTranslator. That already produces the correct KDF-specific model
            // nodes (HKDF/PBKDF1/PBKDF2/KDFCounter, which implement KeyDerivationFunction /
            // PasswordBasedKeyDerivationFunction in the mapper model), so no information is lost
            // by not using this context. This branch is a deliberate, documented no-op — it
            // behaves the same as the default fallthrough below, but exists so this gap reads as
            // an intentional choice rather than a missed dispatch case if a future C# rule ever
            // reaches for KeyDerivationFunctionContext (at which point a real translator, mirroring
            // CSharpKeyContextTranslator's "KDF_*" cases, would need to be wired in here).
            return Optional.empty();
        }

        return Optional.empty();
    }

    @Override
    @Nullable protected DetectionLocation getDetectionContextFrom(
            @Nonnull CSharpTree location, @Nonnull IBundle bundle, @Nonnull String filePath) {
        int lineNumber = location.getLine();
        int offset = location.getColumn();

        List<String> keywords = List.of();
        if (location instanceof CSharpMethodInvocationTree invocation) {
            keywords = List.of(invocation.getMethodName());
        } else if (location instanceof CSharpObjectCreationTree creation) {
            keywords = List.of(creation.getTypeName());
        }

        return new DetectionLocation(filePath, lineNumber, offset, keywords, bundle);
    }
}
