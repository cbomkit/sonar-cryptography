/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2025 PQCA
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

import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DHKEM;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSASVE;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.algorithms.X448;
import com.ibm.mapper.model.functionality.Decapsulate;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.Functionality;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Reorganizer rules for the operations performed with a key, when the operation is found on the
 * key's algorithm rather than named by its own algorithm, e.g. an EC key used to sign.
 */
public final class KeyUsageReorganizer {

    private KeyUsageReorganizer() {
        // private
    }

    /**
     * A reorganizer rule that reports each operation performed with a private key as the algorithm
     * of that operation, held by the key: a signature or its verification with an EC key is ECDSA,
     * with an RSA key an RSA signature (RSA-PSS when that padding is selected); key agreement with
     * an EC key is ECDH and with a DH key DH; key encapsulation with an RSA key is RSASVE and with
     * an EC, X25519 or X448 key DHKEM. The operation algorithm gets the key's curve or key length
     * and the digest the operation uses.
     *
     * <p>The key's algorithm is removed from the key once all its operations are reported this way,
     * as the key is then described by the algorithms of its operations.
     */
    @Nonnull
    public static final IReorganizerRule MAKE_ALGORITHMS_OF_PRIVATE_KEY_OPERATIONS =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule("MAKE_ALGORITHMS_OF_PRIVATE_KEY_OPERATIONS")
                    .forNodeKind(PrivateKey.class)
                    .withDetectionCondition(
                            (node, parent, roots) ->
                                    keyAlgorithm(node)
                                            .map(
                                                    algorithm ->
                                                            operations(algorithm).stream()
                                                                    .anyMatch(
                                                                            operation ->
                                                                                    selectsAnotherAlgorithm(
                                                                                            algorithm,
                                                                                            operation)))
                                            .orElse(false))
                    .perform(
                            (node, parent, roots) -> {
                                final INode algorithm = keyAlgorithm(node).orElseThrow();
                                for (Functionality operation : operations(algorithm)) {
                                    if (!selectsAnotherAlgorithm(algorithm, operation)) {
                                        continue;
                                    }
                                    final INode operationAlgorithm =
                                            operationAlgorithm(algorithm, operation);
                                    algorithm.removeChildOfType(operation.getKind());
                                    moveUnder(operationAlgorithm, operation);
                                    final Optional<INode> sameAlgorithm =
                                            node.hasChildOfType(operationAlgorithm.getKind())
                                                    .filter(
                                                            existing ->
                                                                    existing.getClass()
                                                                            .equals(
                                                                                    operationAlgorithm
                                                                                            .getClass()));
                                    if (sameAlgorithm.isPresent()) {
                                        operationAlgorithm
                                                .getChildren()
                                                .values()
                                                .forEach(sameAlgorithm.get()::put);
                                    } else {
                                        node.put(operationAlgorithm);
                                    }
                                }
                                if (operations(algorithm).isEmpty()) {
                                    algorithm
                                            .hasChildOfType(KeyGeneration.class)
                                            .ifPresent(node::put);
                                    node.removeChildOfType(algorithm.getKind());
                                }
                                return roots;
                            });

    /**
     * A reorganizer rule for a key of the given kind created from raw bytes, i.e. not generated:
     * the operations performed with the key, and the algorithms they use (e.g. the cipher of a CMAC
     * key), are found on the key and are moved under the key's algorithm.
     */
    @Nonnull
    public static IReorganizerRule moveOperationsOfImportedKeyUnderItsAlgorithm(
            @Nonnull Class<? extends Key> keyKind) {
        return new ReorganizerRuleBuilder()
                .createReorganizerRule("MOVE_OPERATIONS_OF_IMPORTED_KEY_UNDER_ITS_ALGORITHM")
                .forNodeKind(keyKind)
                .withDetectionCondition(
                        (node, parent, roots) ->
                                ownAlgorithm(node).isPresent()
                                        && !isGenerated(node)
                                        && !movedUnderAlgorithm(node).isEmpty())
                .perform(
                        (node, parent, roots) -> {
                            final INode algorithm = ownAlgorithm(node).orElseThrow();
                            for (INode child : movedUnderAlgorithm(node)) {
                                algorithm.put(child);
                                node.removeChildOfType(child.getKind());
                            }
                            return roots;
                        });
    }

    /**
     * A reorganizer rule for a MAC key: the signature computed with it through a digest sign
     * operation (e.g. EVP_DigestSign with an HMAC key) is the MAC's tag, computed with the digest
     * of the operation.
     */
    @Nonnull
    public static final IReorganizerRule MAKE_TAGS_OF_SECRET_KEY_OPERATIONS =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule("MAKE_TAGS_OF_SECRET_KEY_OPERATIONS")
                    .forNodeKind(SecretKey.class)
                    .withDetectionCondition(
                            (node, parent, roots) ->
                                    keyAlgorithm(node)
                                            .filter(algorithm -> algorithm.is(Mac.class))
                                            .map(
                                                    algorithm ->
                                                            !signatureOperations(algorithm)
                                                                    .isEmpty())
                                            .orElse(false))
                    .perform(
                            (node, parent, roots) -> {
                                final INode mac = keyAlgorithm(node).orElseThrow();
                                for (Functionality operation : signatureOperations(mac)) {
                                    mac.removeChildOfType(operation.getKind());
                                    for (INode used :
                                            List.copyOf(operation.getChildren().values())) {
                                        mac.put(used);
                                    }
                                    mac.put(new Tag(operation.getDetectionContext()));
                                }
                                return roots;
                            });

    /** The algorithm a key was created with, which gives the key its name. */
    @Nonnull
    private static Optional<INode> ownAlgorithm(@Nonnull INode key) {
        return key.getChildren().values().stream()
                .filter(IAlgorithm.class::isInstance)
                .filter(child -> ((IAlgorithm) child).getName().equals(key.asString()))
                .findFirst();
    }

    private static boolean isGenerated(@Nonnull INode key) {
        return key.hasChildOfType(KeyGeneration.class).isPresent()
                || ownAlgorithm(key)
                        .flatMap(algorithm -> algorithm.hasChildOfType(KeyGeneration.class))
                        .isPresent();
    }

    /** The operations and used algorithms found on a key, other than its own algorithm. */
    @Nonnull
    private static List<INode> movedUnderAlgorithm(@Nonnull INode key) {
        final Optional<INode> own = ownAlgorithm(key);
        return key.getChildren().values().stream()
                .filter(child -> own.map(algorithm -> algorithm != child).orElse(true))
                .filter(
                        child ->
                                (child instanceof Functionality
                                                && !(child instanceof KeyGeneration))
                                        || child instanceof IAlgorithm)
                .toList();
    }

    @Nonnull
    private static List<Functionality> signatureOperations(@Nonnull INode algorithm) {
        return algorithm.getChildren().values().stream()
                .filter(child -> child instanceof Sign || child instanceof Verify)
                .map(Functionality.class::cast)
                .toList();
    }

    @Nonnull
    private static Optional<INode> keyAlgorithm(@Nonnull INode key) {
        return key.getChildren().values().stream().filter(IAlgorithm.class::isInstance).findFirst();
    }

    /** The operations found on an algorithm, other than the generation of the key. */
    @Nonnull
    private static List<Functionality> operations(@Nonnull INode algorithm) {
        return algorithm.getChildren().values().stream()
                .filter(Functionality.class::isInstance)
                .filter(child -> !(child instanceof KeyGeneration))
                .map(Functionality.class::cast)
                .toList();
    }

    /**
     * Whether an operation performed with a key of the given algorithm has another algorithm than
     * the key's, i.e. not e.g. an Ed25519 signature or an X25519 key agreement.
     */
    private static boolean selectsAnotherAlgorithm(
            @Nonnull INode algorithm, @Nonnull Functionality operation) {
        if (operation instanceof Sign || operation instanceof Verify) {
            return algorithm instanceof EllipticCurveAlgorithm
                    || (algorithm instanceof RSA && !algorithm.is(Signature.class));
        } else if (operation instanceof KeyDerivation) {
            return algorithm instanceof EllipticCurveAlgorithm
                    || (algorithm instanceof DH && !algorithm.is(KeyAgreement.class));
        } else if (operation instanceof Encapsulate || operation instanceof Decapsulate) {
            return algorithm instanceof RSA
                    || algorithm instanceof EllipticCurveAlgorithm
                    || algorithm instanceof X25519
                    || algorithm instanceof X448;
        }
        return false;
    }

    /**
     * The algorithm of an operation performed with a key of the given algorithm, for an operation
     * that {@link #selectsAnotherAlgorithm selects another algorithm}. An RSA-PSS scheme selected
     * for the operation is taken from the operation.
     */
    @Nonnull
    private static INode operationAlgorithm(
            @Nonnull INode algorithm, @Nonnull Functionality operation) {
        final DetectionLocation location = operation.getDetectionContext();
        if (operation instanceof Sign || operation instanceof Verify) {
            if (algorithm instanceof EllipticCurveAlgorithm) {
                return withCurveOf(algorithm, new ECDSA(location));
            }
            if (algorithm instanceof RSA && !algorithm.is(Signature.class)) {
                final Optional<INode> pss =
                        operation.hasChildOfType(ProbabilisticSignatureScheme.class);
                if (pss.isPresent()) {
                    operation.removeChildOfType(ProbabilisticSignatureScheme.class);
                    return withKeyLengthOf(algorithm, pss.get());
                }
                return withKeyLengthOf(algorithm, new RSA(Signature.class, location));
            }
        } else if (operation instanceof KeyDerivation) {
            if (algorithm instanceof EllipticCurveAlgorithm) {
                return withCurveOf(algorithm, new ECDH(location));
            }
            if (algorithm instanceof DH && !algorithm.is(KeyAgreement.class)) {
                return withKeyLengthOf(algorithm, new DH(KeyAgreement.class, location));
            }
        } else if (operation instanceof Encapsulate || operation instanceof Decapsulate) {
            if (algorithm instanceof RSA) {
                return withKeyLengthOf(algorithm, new RSASVE(location));
            }
            if (algorithm instanceof EllipticCurveAlgorithm) {
                return new DHKEM(withCurveOf(algorithm, new ECDH(location)), location);
            }
            if (algorithm instanceof X25519 || algorithm instanceof X448) {
                return new DHKEM(withoutOperations(algorithm.deepCopy()), location);
            }
        }
        throw new IllegalArgumentException(
                "no other algorithm for " + operation.asString() + " with " + algorithm.asString());
    }

    /** The algorithm without the operations performed with it, e.g. for use inside DHKEM. */
    @Nonnull
    private static INode withoutOperations(@Nonnull INode algorithm) {
        algorithm.getChildren().values().stream()
                .filter(Functionality.class::isInstance)
                .map(INode::getKind)
                .toList()
                .forEach(algorithm::removeChildOfType);
        return algorithm;
    }

    @Nonnull
    private static INode withCurveOf(@Nonnull INode key, @Nonnull INode operationAlgorithm) {
        key.hasChildOfType(EllipticCurve.class)
                .ifPresent(curve -> operationAlgorithm.put(curve.deepCopy()));
        return operationAlgorithm;
    }

    @Nonnull
    private static INode withKeyLengthOf(@Nonnull INode key, @Nonnull INode operationAlgorithm) {
        if (operationAlgorithm.hasChildOfType(KeyLength.class).isEmpty()) {
            key.hasChildOfType(KeyLength.class)
                    .ifPresent(keyLength -> operationAlgorithm.put(keyLength.deepCopy()));
        }
        return operationAlgorithm;
    }

    /** Puts the operation under its algorithm, together with what it uses, e.g. its digest. */
    private static void moveUnder(@Nonnull INode operationAlgorithm, @Nonnull INode operation) {
        for (INode used : List.copyOf(operation.getChildren().values())) {
            operationAlgorithm.put(used);
            operation.removeChildOfType(used.getKind());
        }
        operationAlgorithm.put(operation);
    }
}
