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

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.algorithms.X448;
import com.ibm.mapper.model.curves.Curve25519;
import com.ibm.mapper.model.curves.Curve448;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import javax.annotation.Nonnull;

public final class KeyAgreementReorganizer {

    private KeyAgreementReorganizer() {
        // nothing
    }

    public static final IReorganizerRule MERGE_KEYAGREEMENT_WITH_PKE_UNDER_PRIVATE_KEY =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(PrivateKey.class)
                    .withDetectionCondition(
                            (node, parent, roots) ->
                                    node.hasChildOfType(PublicKeyEncryption.class).isPresent()
                                            && node.hasChildOfType(KeyAgreement.class).isPresent())
                    .perform(
                            (node, parent, roots) -> {
                                final Optional<INode> pke =
                                        node.hasChildOfType(PublicKeyEncryption.class);
                                final Optional<INode> ka = node.hasChildOfType(KeyAgreement.class);
                                if (pke.isPresent() && ka.isPresent()) {
                                    pke.get()
                                            .hasChildOfType(EllipticCurve.class)
                                            .ifPresent(e -> ka.get().put(e));
                                    node.removeChildOfType(pke.get().getKind());
                                }
                                return roots;
                            });

    public static final IReorganizerRule REPLACE_ECDH_WITH_X25519_WHEN_CURVE25519 =
            replaceEcdhWithXdh(Curve25519.class, X25519::new);

    public static final IReorganizerRule REPLACE_ECDH_WITH_X448_WHEN_CURVE448 =
            replaceEcdhWithXdh(Curve448.class, X448::new);

    /**
     * Returns a rule that replaces an {@link ECDH} key-agreement root node with a specific XDH
     * algorithm node when both its {@link PrivateKey} and {@link PublicKey} children carry the
     * given {@code curveKind}. The replacement node is constructed via {@code xdhSupplier}, which
     * is expected to set the correct canonical OID and curve; all other children ({@code
     * KeyGeneration}, {@code PrivateKey}, {@code PublicKey}) are transferred from the old node.
     *
     * @param curveKind the {@link EllipticCurve} subclass to match on both key children
     * @param xdhSupplier factory that builds the replacement node from a {@link
     *     com.ibm.mapper.utils.DetectionLocation}
     */
    @Nonnull
    public static IReorganizerRule replaceEcdhWithXdh(
            @Nonnull Class<? extends EllipticCurve> curveKind,
            @Nonnull Function<DetectionLocation, ? extends Algorithm> xdhSupplier) {
        return new ReorganizerRuleBuilder()
                .createReorganizerRule("REPLACE_ECDH_WITH_XDH_WHEN_" + curveKind.getSimpleName())
                .forNodeKind(KeyAgreement.class)
                .withDetectionCondition(
                        (node, parent, roots) ->
                                node instanceof ECDH
                                        && hasCurveInKey(node, PrivateKey.class, curveKind)
                                        && hasCurveInKey(node, PublicKey.class, curveKind))
                .perform(
                        (node, parent, roots) -> {
                            Algorithm xdh = xdhSupplier.apply(((ECDH) node).getDetectionContext());
                            transferChildren(node, xdh);
                            return replaceRoot(roots, node, xdh);
                        });
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    /**
     * Returns {@code true} when {@code ecdh} has a {@code keyKind} child whose own {@code
     * PublicKeyEncryption} child contains an {@link EllipticCurve} child that is an instance of
     * {@code curveKind}.
     */
    private static boolean hasCurveInKey(
            @Nonnull INode ecdh,
            @Nonnull Class<? extends INode> keyKind,
            @Nonnull Class<? extends EllipticCurve> curveKind) {
        return ecdh.hasChildOfType(keyKind)
                .flatMap(key -> key.hasChildOfType(PublicKeyEncryption.class))
                .flatMap(pke -> pke.hasChildOfType(EllipticCurve.class))
                .filter(curveKind::isInstance)
                .isPresent();
    }

    /**
     * Copies all children of {@code source} into {@code target}, skipping {@link Oid} so that the
     * target's own canonical OID (set by its constructor) is preserved.
     */
    private static void transferChildren(@Nonnull INode source, @Nonnull INode target) {
        source.getChildren().entrySet().stream()
                .filter(e -> !e.getKey().equals(Oid.class))
                .forEach(e -> target.put(e.getValue()));
    }

    /** Returns a new roots list with {@code oldNode} replaced by {@code newNode}. */
    @Nonnull
    private static List<INode> replaceRoot(
            @Nonnull List<INode> roots, @Nonnull INode oldNode, @Nonnull INode newNode) {
        List<INode> newRoots = new LinkedList<>(roots);
        newRoots.replaceAll(r -> r == oldNode ? newNode : r);
        return newRoots;
    }
}
