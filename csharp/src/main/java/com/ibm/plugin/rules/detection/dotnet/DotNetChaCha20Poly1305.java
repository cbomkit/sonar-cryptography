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
package com.ibm.plugin.rules.detection.dotnet;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for {@code ChaCha20Poly1305} in System.Security.Cryptography.
 *
 * <p>{@code ChaCha20Poly1305} is a sealed AEAD cipher class (available since .NET 6, platform gated
 * by {@code IsSupported}), structurally analogous to {@code AesGcm}/{@code AesCcm} in {@link
 * DotNetAES}: it is constructed from a key and exposes {@code Encrypt}/{@code Decrypt} methods
 * taking nonce, plaintext/ciphertext, tag and an optional associated-data buffer. There is no class
 * hierarchy to cover (the class is {@code sealed}), and no inherited {@code SymmetricAlgorithm}
 * surface (property setters, {@code CreateEncryptor}, mode-specific Encrypt/Decrypt, etc.) applies
 * here.
 *
 * <p>Constructors covered:
 *
 * <ul>
 *   <li>{@code ChaCha20Poly1305(byte[] key)}
 *   <li>{@code ChaCha20Poly1305(ReadOnlySpan<byte> key)}
 * </ul>
 *
 * Both take exactly one parameter, so a single rule using {@code withAnyParameters()} covers both
 * overloads (parameter types are not resolvable by the engine — see {@code
 * CSharpLanguageTranslation}).
 *
 * <p>The static {@code IsSupported} property is a platform-availability check, not
 * detection-relevant cryptographic information, and is intentionally not modeled (mirrors how
 * KMAC/SHA-3 platform-support properties are ignored elsewhere in this module).
 *
 * <p>Operations covered as depending rules (fired only on a tracked {@code ChaCha20Poly1305}
 * variable), mirroring the {@code AesGcm}/{@code AesCcm} pattern in {@link DotNetAES}:
 *
 * <ul>
 *   <li>{@code Encrypt(nonce, plaintext, ciphertext, tag [, associatedData])} — both the {@code
 *       byte[]} and {@code ReadOnlySpan<byte>} overloads always declare all five parameters (the
 *       last one defaults to {@code null}/{@code default}), but callers may omit the trailing
 *       associated-data argument at the call site, so {@code withAnyParameters()} is used to match
 *       both the 4- and 5-argument call shapes, exactly like {@code AesGcm.Encrypt}.
 *   <li>{@code Decrypt(nonce, ciphertext, tag, plaintext [, associatedData])} — same reasoning.
 * </ul>
 *
 * <p>Known gap: nonce length (fixed at 12 bytes), tag length (fixed at 16 bytes) and the
 * associated-data content are not captured as separate values. As with {@code AesGcm}/{@code
 * AesCcm}, these arguments are almost always local {@code byte[]} variables (e.g. {@code new
 * byte[12]}) rather than literals passed directly into {@code Encrypt}/{@code Decrypt}, and the
 * engine cannot resolve values across variable assignments (see {@code CSharpSymbol}). // TODO:
 * ChaCha20Poly1305 nonce/tag length capture is not possible with the current engine and is left as
 * a known gap, consistent with the same limitation for AesGcm/AesCcm.
 */
public final class DotNetChaCha20Poly1305 {

    private DotNetChaCha20Poly1305() {
        // nothing
    }

    // =========================================================================
    // ChaCha20Poly1305 AEAD operation rules
    // =========================================================================

    // chaCha20Poly1305.Encrypt(nonce, plaintext, ciphertext, tag [, associatedData])
    private static final IDetectionRule<CSharpTree> CHACHA20POLY1305_ENCRYPT_OP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("Encrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // chaCha20Poly1305.Decrypt(nonce, ciphertext, tag, plaintext [, associatedData])
    private static final IDetectionRule<CSharpTree> CHACHA20POLY1305_DECRYPT_OP =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("Decrypt")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> CHACHA20POLY1305_OP_RULES =
            List.of(CHACHA20POLY1305_ENCRYPT_OP, CHACHA20POLY1305_DECRYPT_OP);

    // =========================================================================
    // Primary creation rule
    // =========================================================================

    // new ChaCha20Poly1305(key) — AEAD (byte[] or ReadOnlySpan<Byte>, 1 param)
    private static final IDetectionRule<CSharpTree> CHACHA20_POLY1305 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("ChaCha20Poly1305")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CHACHA20-POLY1305"))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(CHACHA20POLY1305_OP_RULES);

    @Nonnull
    public static List<IDetectionRule<CSharpTree>> rules() {
        return List.of(CHACHA20_POLY1305);
    }
}
