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
package com.ibm.output.behavior;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.KeyWrap;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.model.functionality.Decapsulate;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.mapper.model.functionality.Verify;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import javax.annotation.Nonnull;

/**
 * Derives {@link CryptoBehavior}s for a detected cryptographic asset. Operation-first: every {@code
 * OPERATIONS} row whose {@code Functionality} child is present and whose guard holds contributes.
 * If no operation matched, the ordered {@code FALLBACKS} table infers plausible behaviors from the
 * primitive kind (first matching kind wins). Never throws; unmappable input yields an empty set.
 * Note: {@code authenticates} is deliberately never derived here — it is an application-level
 * behavior gated on auth-interface evidence (see {@code AuthInterfaceRule}).
 */
public final class CryptoBehaviorMapper {

    public static final String BEHAVIOR_PROPERTY_NAME = "cbomkit:crypto:behavior";

    private static final Predicate<INode> ANY = node -> true;

    private static final Predicate<INode> IS_KEM = node -> node.is(KeyEncapsulationMechanism.class);

    private static final Predicate<INode> IS_CIPHER =
            node ->
                    node.is(BlockCipher.class)
                            || node.is(StreamCipher.class)
                            || node.is(Cipher.class)
                            || node.is(AuthenticatedEncryption.class)
                            || node.is(KeyWrap.class);

    private static final Predicate<INode> IS_PRNG =
            node -> node.is(PseudorandomNumberGenerator.class);

    private static final Predicate<INode> IS_PASSWORD_KDF =
            node ->
                    node.is(PasswordBasedKeyDerivationFunction.class)
                            || node.is(PasswordBasedEncryption.class);

    private record OperationMapping(
            @Nonnull Class<? extends INode> operation,
            @Nonnull Predicate<INode> when,
            @Nonnull Set<CryptoBehavior> behaviors) {}

    private record FallbackMapping(
            @Nonnull Class<? extends INode> primitive, @Nonnull Set<CryptoBehavior> behaviors) {}

    /** Operational pass (spec §5.1) — all matching rows contribute. */
    private static final List<OperationMapping> OPERATIONS =
            List.of(
                    on(
                            Encrypt.class,
                            ANY,
                            CryptoBehavior.ENCRYPTS_DATA,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    on(
                            Decrypt.class,
                            ANY,
                            CryptoBehavior.DECRYPTS_DATA,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    on(
                            Encapsulate.class,
                            IS_KEM,
                            CryptoBehavior.EXCHANGES_KEY,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    on(
                            Decapsulate.class,
                            IS_KEM,
                            CryptoBehavior.EXCHANGES_KEY,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    // JCA WRAP_MODE/UNWRAP_MODE and Cipher.wrap surface as (De)Encapsulate on a
                    // Cipher.
                    on(Encapsulate.class, IS_CIPHER, CryptoBehavior.WRAPS_KEY),
                    on(Decapsulate.class, IS_CIPHER, CryptoBehavior.WRAPS_KEY),
                    on(
                            Sign.class,
                            ANY,
                            CryptoBehavior.SIGNS_DATA,
                            CryptoBehavior.ENSURES_INTEGRITY,
                            CryptoBehavior.ENSURES_NON_REPUDIATION),
                    on(
                            Verify.class,
                            ANY,
                            CryptoBehavior.VERIFIES_SIGNATURE,
                            CryptoBehavior.ENSURES_INTEGRITY),
                    on(
                            Digest.class,
                            ANY,
                            CryptoBehavior.HASHES_DATA,
                            CryptoBehavior.ENSURES_INTEGRITY),
                    // No operational "computesMac" verb in the taxonomy, and authenticates is
                    // gated on auth-interface evidence — a Tag contributes integrity only.
                    on(Tag.class, ANY, CryptoBehavior.ENSURES_INTEGRITY),
                    on(Generate.class, IS_PRNG, CryptoBehavior.GENERATES_RANDOM_VALUE),
                    on(KeyGeneration.class, ANY, CryptoBehavior.GENERATES_KEY),
                    on(KeyDerivation.class, IS_PASSWORD_KDF, CryptoBehavior.HASHES_PASSWORD),
                    // Generic KDF has no "deriveKey" value; approximated as generatesKey (spec
                    // §5.1).
                    on(
                            KeyDerivation.class,
                            IS_PASSWORD_KDF.negate(),
                            CryptoBehavior.GENERATES_KEY));

    /** Primitive-kind fallback (spec §5.2) — ordered, the first matching kind wins. */
    private static final List<FallbackMapping> FALLBACKS =
            List.of(
                    fallback(
                            AuthenticatedEncryption.class,
                            CryptoBehavior.ENCRYPTS_DATA,
                            CryptoBehavior.DECRYPTS_DATA,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY,
                            CryptoBehavior.ENSURES_INTEGRITY),
                    fallback(
                            BlockCipher.class,
                            CryptoBehavior.ENCRYPTS_DATA,
                            CryptoBehavior.DECRYPTS_DATA,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    fallback(
                            StreamCipher.class,
                            CryptoBehavior.ENCRYPTS_DATA,
                            CryptoBehavior.DECRYPTS_DATA,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    fallback(
                            Cipher.class,
                            CryptoBehavior.ENCRYPTS_DATA,
                            CryptoBehavior.DECRYPTS_DATA,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    fallback(
                            PublicKeyEncryption.class,
                            CryptoBehavior.ENCRYPTS_DATA,
                            CryptoBehavior.DECRYPTS_DATA,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    fallback(
                            Signature.class,
                            CryptoBehavior.SIGNS_DATA,
                            CryptoBehavior.VERIFIES_SIGNATURE,
                            CryptoBehavior.ENSURES_INTEGRITY,
                            CryptoBehavior.ENSURES_NON_REPUDIATION),
                    fallback(
                            ProbabilisticSignatureScheme.class,
                            CryptoBehavior.SIGNS_DATA,
                            CryptoBehavior.VERIFIES_SIGNATURE,
                            CryptoBehavior.ENSURES_INTEGRITY,
                            CryptoBehavior.ENSURES_NON_REPUDIATION),
                    fallback(
                            MessageDigest.class,
                            CryptoBehavior.HASHES_DATA,
                            CryptoBehavior.ENSURES_INTEGRITY),
                    // A bare MAC ensures integrity; authenticates is gated on auth-interface
                    // evidence.
                    fallback(Mac.class, CryptoBehavior.ENSURES_INTEGRITY),
                    fallback(
                            KeyEncapsulationMechanism.class,
                            CryptoBehavior.EXCHANGES_KEY,
                            CryptoBehavior.ENSURES_CONFIDENTIALITY),
                    fallback(KeyWrap.class, CryptoBehavior.WRAPS_KEY),
                    fallback(KeyAgreement.class, CryptoBehavior.EXCHANGES_KEY),
                    fallback(
                            PasswordBasedKeyDerivationFunction.class,
                            CryptoBehavior.HASHES_PASSWORD),
                    fallback(PasswordBasedEncryption.class, CryptoBehavior.HASHES_PASSWORD),
                    fallback(KeyDerivationFunction.class, CryptoBehavior.GENERATES_KEY),
                    fallback(
                            PseudorandomNumberGenerator.class,
                            CryptoBehavior.GENERATES_RANDOM_VALUE));

    @Nonnull
    public Set<CryptoBehavior> map(@Nonnull INode node) {
        final Set<CryptoBehavior> behaviors = EnumSet.noneOf(CryptoBehavior.class);
        if (!(node instanceof Algorithm)) {
            return behaviors;
        }
        final Map<Class<? extends INode>, INode> children = node.getChildren();
        for (OperationMapping row : OPERATIONS) {
            if (children.containsKey(row.operation()) && row.when().test(node)) {
                behaviors.addAll(row.behaviors());
            }
        }
        if (behaviors.isEmpty()) {
            for (FallbackMapping row : FALLBACKS) {
                if (node.is(row.primitive())) {
                    behaviors.addAll(row.behaviors());
                    break;
                }
            }
        }
        return behaviors;
    }

    private static OperationMapping on(
            @Nonnull Class<? extends INode> operation,
            @Nonnull Predicate<INode> when,
            @Nonnull CryptoBehavior... behaviors) {
        return new OperationMapping(operation, when, Set.of(behaviors));
    }

    private static FallbackMapping fallback(
            @Nonnull Class<? extends INode> primitive, @Nonnull CryptoBehavior... behaviors) {
        return new FallbackMapping(primitive, Set.of(behaviors));
    }
}
