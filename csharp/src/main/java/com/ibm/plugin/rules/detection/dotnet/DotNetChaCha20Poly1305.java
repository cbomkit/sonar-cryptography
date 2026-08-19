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
package com.ibm.plugin.rules.detection.dotnet;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for {@code System.Security.Cryptography.ChaCha20Poly1305}.
 *
 * <p>{@code Encrypt}/{@code Decrypt} are expressed as depending rules attached to the
 * constructor, mirroring how {@code AesGcm}/{@code AesCcm} model their AEAD operations in {@link
 * DotNetAES}: the operation is captured as a child of the constructing detection instead of an
 * independent, disconnected top-level finding, so the CBOM ends up with one {@code
 * ChaCha20-Poly1305} node carrying nested {@code Encrypt}/{@code Decrypt} functionality nodes.
 */
public final class DotNetChaCha20Poly1305 {
    private DotNetChaCha20Poly1305() {
        // nothing
    }

    // chaCha20Poly1305.Encrypt(nonce, plaintext, ciphertext, tag [, associatedData])
    private static final IDetectionRule<CSharpTree> CHACHA20POLY1305_ENCRYPT_OP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("Encrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ENCRYPT"))
                    .withAnyParameters() // Byte[] or ReadOnlySpan<Byte> overloads
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // chaCha20Poly1305.Decrypt(nonce, ciphertext, tag, plaintext [, associatedData])
    private static final IDetectionRule<CSharpTree> CHACHA20POLY1305_DECRYPT_OP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("Decrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>("DECRYPT"))
                    .withAnyParameters() // Byte[] or ReadOnlySpan<Byte> overloads
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> CHACHA20POLY1305_OP_RULES =
            List.of(CHACHA20POLY1305_ENCRYPT_OP, CHACHA20POLY1305_DECRYPT_OP);

    // new ChaCha20Poly1305(key)
    private static final IDetectionRule<CSharpTree> CHACHA20POLY1305 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ChaCha20Poly1305")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CHACHA20POLY1305"))
                    .withAnyParameters() // Byte[] or ReadOnlySpan<Byte>, 1 parameter
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(CHACHA20POLY1305_OP_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(CHACHA20POLY1305);
    }
}
