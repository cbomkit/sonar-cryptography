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
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.KeyDerivationFunctionContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.translation.translator.contexts.PycaCipherContextTranslator;
import com.ibm.plugin.translation.translator.contexts.PycaDigestContextTranslator;
import com.ibm.plugin.translation.translator.contexts.PycaKeyAgreementContextTranslator;
import com.ibm.plugin.translation.translator.contexts.PycaKeyContextTranslator;
import com.ibm.plugin.translation.translator.contexts.PycaKeyDerivationContextTranslator;
import com.ibm.plugin.translation.translator.contexts.PycaMacContextTranslator;
import com.ibm.plugin.translation.translator.contexts.PycaPrivateKeyContextTranslator;
import com.ibm.plugin.translation.translator.contexts.PycaPublicKeyContextTranslator;
import com.ibm.plugin.translation.translator.contexts.PycaRandomContextTranslator;
import com.ibm.plugin.translation.translator.contexts.PycaSecretKeyContextTranslator;
import com.ibm.plugin.translation.translator.contexts.PycaSignatureContextTranslator;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.CallExpression;
import org.sonar.plugins.python.api.tree.Name;
import org.sonar.plugins.python.api.tree.Token;
import org.sonar.plugins.python.api.tree.Tree;

public class PythonTranslator extends ITranslator<PythonCheck, Tree, Symbol, PythonVisitorContext> {

    public PythonTranslator() {
        // nothing
    }

    @Nonnull
    @Override
    public Optional<INode> translate(
            @Nonnull final IBundle bundleIdentifier,
            @Nonnull final IValue<Tree> value,
            @Nonnull final IDetectionContext detectionValueContext,
            @Nonnull final String filePath) {
        DetectionLocation detectionLocation =
                getDetectionContextFrom(value.getLocation(), bundleIdentifier, filePath);
        if (detectionLocation == null) {
            return Optional.empty();
        }

        if (detectionValueContext.is(KeyAgreementContext.class)) {
            final PycaKeyAgreementContextTranslator pycaKeyAgreementContextTranslator =
                    new PycaKeyAgreementContextTranslator();
            return pycaKeyAgreementContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        } else if (detectionValueContext.is(KeyDerivationFunctionContext.class)) {
            final PycaKeyDerivationContextTranslator pycaKeyDerivationContextTranslator =
                    new PycaKeyDerivationContextTranslator();
            return pycaKeyDerivationContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        } else if (detectionValueContext.is(PrivateKeyContext.class)) {
            final PycaPrivateKeyContextTranslator pycaPrivateKeyContextTranslator =
                    new PycaPrivateKeyContextTranslator();
            return pycaPrivateKeyContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        } else if (detectionValueContext.is(SecretKeyContext.class)) {
            final PycaSecretKeyContextTranslator pycaSecretKeyContextTranslator =
                    new PycaSecretKeyContextTranslator();
            return pycaSecretKeyContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        } else if (detectionValueContext.is(PublicKeyContext.class)) {
            final PycaPublicKeyContextTranslator pycaPublicKeyContextTranslator =
                    new PycaPublicKeyContextTranslator();
            return pycaPublicKeyContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        } else if (detectionValueContext.is(KeyContext.class)) {
            final PycaKeyContextTranslator pycaKeyContextTranslator =
                    new PycaKeyContextTranslator();
            return pycaKeyContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        } else if (detectionValueContext.is(DigestContext.class)) {
            final PycaDigestContextTranslator pycaDigestContextTranslator =
                    new PycaDigestContextTranslator();
            return pycaDigestContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        } else if (detectionValueContext.is(SignatureContext.class)) {
            final PycaSignatureContextTranslator pycaSignatureContextTranslator =
                    new PycaSignatureContextTranslator();
            return pycaSignatureContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        } else if (detectionValueContext.is(CipherContext.class)) {
            final PycaCipherContextTranslator pycaCipherContextTranslator =
                    new PycaCipherContextTranslator();
            return pycaCipherContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        } else if (detectionValueContext.is(MacContext.class)) {
            final PycaMacContextTranslator pycaMacContextTranslator =
                    new PycaMacContextTranslator();
            return pycaMacContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        } else if (detectionValueContext.is(PRNGContext.class)) {
            final PycaRandomContextTranslator pycaRandomContextTranslator =
                    new PycaRandomContextTranslator();
            return pycaRandomContextTranslator.translate(
                    bundleIdentifier, value, detectionValueContext, detectionLocation);
        }
        return Optional.empty();
    }

    /**
     * This function gets a detection context from the specified Tree location and file path. <br>
     * <li>It obtains the line number and offset.
     * <li>It also determines the kind of the location and populates a list of keywords accordingly.
     * <li>Finally, it creates a new DetectionContext object using the obtained information and
     *     returns it. If any of the conditions are not met or if an error occurs during the
     *     process, it returns null.
     */
    @Override
    protected @Nullable DetectionLocation getDetectionContextFrom(
            @Nonnull Tree location, @Nonnull IBundle bundle, @Nonnull String filePath) {
        Token firstToken = location.firstToken();
        Token lastToken = location.lastToken();
        if (firstToken != null && lastToken != null) {
            int lineNumber = firstToken.line();
            int offset = firstToken.column();
            List<String> keywords = List.of();
            if (location.getKind() == Tree.Kind.CALL_EXPR) {
                final CallExpression callExpression = (CallExpression) location;
                final Symbol callSymbol = callExpression.calleeSymbol();
                if (callSymbol != null) {
                    keywords = List.of(callSymbol.name());
                } else if (callExpression.callee() instanceof Name nameTree) {
                    keywords = List.of(nameTree.name());
                }
            }
            return new DetectionLocation(filePath, lineNumber, offset, keywords, bundle);
        }
        return null;
    }
}
