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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.Padding;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translates {@link com.ibm.engine.model.context.SignatureContext} detections for .NET APIs.
 *
 * <p>Besides the sign and verify actions themselves, this carries the two parameters that every
 * .NET signing call states explicitly: the {@code HashAlgorithmName} that is signed over, and, for
 * RSA, the {@code RSASignaturePadding}. Both are attached as children of the signature action, so a
 * component records that it signs with, say, SHA-256 and PSS rather than only that it signs.
 */
public final class CSharpSignatureContextTranslator implements IContextTranslation<CSharpTree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<CSharpTree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof SignatureAction<CSharpTree> signatureAction) {
            return switch (signatureAction.getAction()) {
                case SIGN -> Optional.of(new Sign(detectionLocation));
                case VERIFY -> Optional.of(new Verify(detectionLocation));
            };
        } else if (value instanceof Algorithm<?>) {
            // The HashAlgorithmName argument of SignData/VerifyData/SignHash/VerifyHash.
            return DotNetHashAlgorithmNames.parseAsNode(value.asString(), detectionLocation);
        } else if (value instanceof Padding<?>) {
            // RSASignaturePadding.Pkcs1 / .Pss, resolved to the bare member name.
            return DotNetPaddingNames.parse(value.asString(), detectionLocation);
        } else if (value instanceof KeySize<?> keySize) {
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        }

        return Optional.empty();
    }
}
