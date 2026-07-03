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
package com.ibm.output.cyclondx.behavior;

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
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;

/**
 * Derives {@link CryptoBehavior}s for a detected cryptographic asset. Operation-first: reads the
 * asset's {@code Functionality} children and its exact primitive kind. If no operation is present,
 * a primitive-kind fallback infers the plausible behaviors. Never throws; unmappable input yields
 * an empty set. See spec §5 for the mapping tables and known taxonomy gaps.
 */
public final class CryptoBehaviorMapper {

    public static final String BEHAVIOR_PROPERTY_NAME = "cbomkit:crypto:behavior";

    @Nonnull
    public Set<CryptoBehavior> map(@Nonnull INode node) {
        final Set<CryptoBehavior> behaviors = EnumSet.noneOf(CryptoBehavior.class);
        if (!(node instanceof Algorithm)) {
            return behaviors;
        }

        final Map<Class<? extends INode>, INode> children = node.getChildren();
        final boolean isCipher =
                node.is(BlockCipher.class)
                        || node.is(StreamCipher.class)
                        || node.is(Cipher.class)
                        || node.is(AuthenticatedEncryption.class)
                        || node.is(KeyWrap.class);
        final boolean isKem = node.is(KeyEncapsulationMechanism.class);
        final boolean isPrng = node.is(PseudorandomNumberGenerator.class);
        final boolean isPasswordKdf =
                node.is(PasswordBasedKeyDerivationFunction.class)
                        || node.is(PasswordBasedEncryption.class);

        // --- Operational pass (reads detected Functionality children) ---
        if (children.containsKey(Encrypt.class)) {
            behaviors.add(CryptoBehavior.ENCRYPTS_DATA);
            behaviors.add(CryptoBehavior.ENSURES_CONFIDENTIALITY);
        }
        if (children.containsKey(Decrypt.class)) {
            behaviors.add(CryptoBehavior.DECRYPTS_DATA);
            behaviors.add(CryptoBehavior.ENSURES_CONFIDENTIALITY);
        }
        if (children.containsKey(Encapsulate.class) || children.containsKey(Decapsulate.class)) {
            if (isKem) {
                behaviors.add(CryptoBehavior.EXCHANGES_KEY);
                behaviors.add(CryptoBehavior.ENSURES_CONFIDENTIALITY);
            } else if (isCipher) {
                // JCA WRAP_MODE/UNWRAP_MODE and Cipher.wrap surface as (De)Encapsulate on a Cipher.
                behaviors.add(CryptoBehavior.WRAPS_KEY);
            }
        }
        if (children.containsKey(Sign.class)) {
            behaviors.add(CryptoBehavior.SIGNS_DATA);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
            behaviors.add(CryptoBehavior.ENSURES_NON_REPUDIATION);
        }
        if (children.containsKey(Verify.class)) {
            behaviors.add(CryptoBehavior.VERIFIES_SIGNATURE);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
        }
        if (children.containsKey(Digest.class)) {
            behaviors.add(CryptoBehavior.HASHES_DATA);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
        }
        if (children.containsKey(Tag.class)) {
            // No operational "computesMac" verb in the taxonomy; use goal-level behaviors (spec
            // §5.1).
            behaviors.add(CryptoBehavior.AUTHENTICATES);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
        }
        if (children.containsKey(Generate.class) && isPrng) {
            behaviors.add(CryptoBehavior.GENERATES_RANDOM_VALUE);
        }
        if (children.containsKey(KeyGeneration.class)) {
            behaviors.add(CryptoBehavior.GENERATES_KEY);
        }
        if (children.containsKey(KeyDerivation.class)) {
            // Generic KDF has no "deriveKey" value; approximated as generatesKey (spec §5.1).
            behaviors.add(
                    isPasswordKdf ? CryptoBehavior.HASHES_PASSWORD : CryptoBehavior.GENERATES_KEY);
        }

        // --- Primitive-kind fallback (only when no operation was detected) ---
        if (behaviors.isEmpty()) {
            applyPrimitiveFallback(node, behaviors);
        }
        return behaviors;
    }

    private void applyPrimitiveFallback(
            @Nonnull INode node, @Nonnull Set<CryptoBehavior> behaviors) {
        if (node.is(AuthenticatedEncryption.class)) {
            behaviors.add(CryptoBehavior.ENCRYPTS_DATA);
            behaviors.add(CryptoBehavior.DECRYPTS_DATA);
            behaviors.add(CryptoBehavior.ENSURES_CONFIDENTIALITY);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
        } else if (node.is(BlockCipher.class)
                || node.is(StreamCipher.class)
                || node.is(Cipher.class)
                || node.is(PublicKeyEncryption.class)) {
            behaviors.add(CryptoBehavior.ENCRYPTS_DATA);
            behaviors.add(CryptoBehavior.DECRYPTS_DATA);
            behaviors.add(CryptoBehavior.ENSURES_CONFIDENTIALITY);
        } else if (node.is(Signature.class) || node.is(ProbabilisticSignatureScheme.class)) {
            behaviors.add(CryptoBehavior.SIGNS_DATA);
            behaviors.add(CryptoBehavior.VERIFIES_SIGNATURE);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
            behaviors.add(CryptoBehavior.ENSURES_NON_REPUDIATION);
        } else if (node.is(MessageDigest.class)) {
            behaviors.add(CryptoBehavior.HASHES_DATA);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
        } else if (node.is(Mac.class)) {
            behaviors.add(CryptoBehavior.AUTHENTICATES);
            behaviors.add(CryptoBehavior.ENSURES_INTEGRITY);
        } else if (node.is(KeyEncapsulationMechanism.class)) {
            behaviors.add(CryptoBehavior.EXCHANGES_KEY);
            behaviors.add(CryptoBehavior.ENSURES_CONFIDENTIALITY);
        } else if (node.is(KeyWrap.class)) {
            behaviors.add(CryptoBehavior.WRAPS_KEY);
        } else if (node.is(KeyAgreement.class)) {
            behaviors.add(CryptoBehavior.EXCHANGES_KEY);
        } else if (node.is(PasswordBasedKeyDerivationFunction.class)
                || node.is(PasswordBasedEncryption.class)) {
            behaviors.add(CryptoBehavior.HASHES_PASSWORD);
        } else if (node.is(KeyDerivationFunction.class)) {
            behaviors.add(CryptoBehavior.GENERATES_KEY);
        } else if (node.is(PseudorandomNumberGenerator.class)) {
            behaviors.add(CryptoBehavior.GENERATES_RANDOM_VALUE);
        }
    }
}
