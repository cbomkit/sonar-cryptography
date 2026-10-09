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
package com.ibm.mapper.reorganizer.rules;

import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.algorithms.Blowfish;
import com.ibm.mapper.model.algorithms.RC2;
import com.ibm.mapper.model.algorithms.RC4;
import com.ibm.mapper.model.algorithms.RC5;
import com.ibm.mapper.model.algorithms.cast.CAST128;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.UsualPerformActions;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class CipherParameterReorganizer {

    private CipherParameterReorganizer() {
        // private
    }

    /* Used for AEADParameters */
    @Nonnull
    public static final IReorganizerRule MOVE_KEY_LENGTH_UNDER_TAG_LENGTH_UP =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(TagLength.class)
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(KeyLength.class)
                                            .noAction()))
                    .perform(
                            (node, parent, roots) -> {
                                INode keyLengthChild = node.getChildren().get(KeyLength.class);
                                if (parent == null) {
                                    // Do nothing
                                    return roots;
                                } else {
                                    // Append the KeyLength to the parent and remove it from the
                                    // TagLength node
                                    parent.put(keyLengthChild);
                                    node.removeChildOfType(KeyLength.class);
                                    return roots;
                                }
                            });

    /**
     * A key length set for an encryption with a cipher (in C, {@code EVP_CIPHER_CTX_set_key_length}
     * on the context the cipher is initialized on) is the key length of a cipher whose key length
     * is variable: RC2, RC4, RC5, Blowfish and CAST5, the ciphers OpenSSL marks {@code
     * EVP_CIPH_VARIABLE_LENGTH}. A cipher whose key length is fixed keeps the key length it has, as
     * OpenSSL refuses another one.
     */
    @Nonnull
    public static final IReorganizerRule KEEP_THE_FIXED_KEY_LENGTH_OF_THE_CIPHER_OF_AN_ENCRYPTION =
            keepTheFixedKeyLengthOfTheCipher(Encrypt.class);

    @Nonnull
    public static final IReorganizerRule KEEP_THE_FIXED_KEY_LENGTH_OF_THE_CIPHER_OF_A_DECRYPTION =
            keepTheFixedKeyLengthOfTheCipher(Decrypt.class);

    @Nonnull
    private static IReorganizerRule keepTheFixedKeyLengthOfTheCipher(
            @Nonnull Class<? extends INode> operationClazz) {
        return new ReorganizerRuleBuilder()
                .createReorganizerRule()
                .forNodeKind(operationClazz)
                .withDetectionCondition(
                        (node, parent, roots) ->
                                parent instanceof IAlgorithm
                                        && parent.hasChildOfType(KeyLength.class).isPresent()
                                        && node.hasChildOfType(KeyLength.class).isPresent()
                                        && !hasVariableKeyLength(parent))
                .perform(
                        (node, parent, roots) -> {
                            node.removeChildOfType(KeyLength.class);
                            return roots;
                        });
    }

    private static boolean hasVariableKeyLength(@Nonnull INode cipher) {
        return cipher instanceof RC2
                || cipher instanceof RC4
                || cipher instanceof RC5
                || cipher instanceof Blowfish
                || cipher instanceof CAST128;
    }

    @Nonnull
    public static final IReorganizerRule MOVE_NODES_UNDER_ENCRYPT_UP =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Encrypt.class)
                    .withAnyNonNullChildren()
                    .perform(UsualPerformActions.performMovingChildrenUp);

    @Nonnull
    public static final IReorganizerRule MOVE_NODES_UNDER_DECRYPT_UP =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Decrypt.class)
                    .withAnyNonNullChildren()
                    .perform(UsualPerformActions.performMovingChildrenUp);

    /**
     * An encryption or decryption operation detected before the cipher it uses (as in C, where
     * {@code EVP_EncryptInit_ex(ctx, cipher, ...)} names the cipher) has the cipher as its child.
     * The cipher becomes the root node and the operation its child, the same shape as when the
     * cipher is detected first.
     */
    @Nonnull
    public static final IReorganizerRule MOVE_ENCRYPT_UNDER_ITS_CIPHER =
            moveOperationUnderItsCipher(Encrypt.class);

    @Nonnull
    public static final IReorganizerRule MOVE_DECRYPT_UNDER_ITS_CIPHER =
            moveOperationUnderItsCipher(Decrypt.class);

    @Nonnull
    private static IReorganizerRule moveOperationUnderItsCipher(
            @Nonnull Class<? extends INode> operationClazz) {
        return new ReorganizerRuleBuilder()
                .createReorganizerRule()
                .forNodeKind(operationClazz)
                .withDetectionCondition(
                        (node, parent, roots) -> parent == null && cipherOf(node).isPresent())
                .perform(
                        (node, parent, roots) -> {
                            final INode cipher = cipherOf(node).orElseThrow();
                            node.removeChildOfType(cipher.getKind());
                            cipher.put(node);
                            final List<INode> newRoots = new ArrayList<>(roots);
                            newRoots.replaceAll(root -> root == node ? cipher : root);
                            return newRoots;
                        });
    }

    @Nonnull
    private static Optional<INode> cipherOf(@Nonnull INode operation) {
        return operation.getChildren().values().stream()
                .filter(IAlgorithm.class::isInstance)
                .findFirst();
    }
}
