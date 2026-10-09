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

import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.functionality.Functionality;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.UsualPerformActions;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class SignatureReorganizer {

    private SignatureReorganizer() {
        // private
    }

    @Nonnull
    public static final IReorganizerRule MERGE_UNKNOWN_SIGNATURE_PARENT_AND_CHILD =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule("MERGE_SIGNATURE_UNKNOWN_PARENT_AND_CHILD")
                    .forNodeKind(Signature.class)
                    .forNodeValue(ITranslator.UNKNOWN)
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(Signature.class)
                                            .noAction()))
                    .perform(
                            UsualPerformActions.performMergeParentAndChildOfSameKind(
                                    Signature.class));

    /**
     * A signature or its verification found with no algorithm holding it, e.g. made with a key
     * whose type is not known in the analyzed code: a signature scheme the operation names (e.g.
     * RSA-PSS, selected by the padding set for it) holds the operation and what it uses, else a
     * signature of an unknown scheme does, with the digest the operation uses.
     */
    @Nonnull
    public static final IReorganizerRule MAKE_SIGNATURE_OF_A_SIGNING_OPERATION_WITHOUT_SCHEME =
            signatureOfOperationWithoutScheme(Sign.class);

    @Nonnull
    public static final IReorganizerRule MAKE_SIGNATURE_OF_A_VERIFYING_OPERATION_WITHOUT_SCHEME =
            signatureOfOperationWithoutScheme(Verify.class);

    @Nonnull
    private static IReorganizerRule signatureOfOperationWithoutScheme(
            @Nonnull Class<? extends Functionality> operationClazz) {
        return new ReorganizerRuleBuilder()
                .createReorganizerRule()
                .forNodeKind(operationClazz)
                .withDetectionCondition((node, parent, roots) -> parent == null)
                .perform(
                        (node, parent, roots) -> {
                            final INode signature =
                                    schemeOf(node)
                                            .orElseGet(
                                                    () ->
                                                            new Algorithm(
                                                                    ITranslator.UNKNOWN,
                                                                    Signature.class,
                                                                    ((Functionality) node)
                                                                            .getDetectionContext()));
                            node.removeChildOfType(signature.getKind());
                            for (INode used : List.copyOf(node.getChildren().values())) {
                                signature.put(used);
                                node.removeChildOfType(used.getKind());
                            }
                            signature.put(node);
                            final List<INode> newRoots = new LinkedList<>(roots);
                            newRoots.replaceAll(root -> root == node ? signature : root);
                            return newRoots;
                        });
    }

    /** The signature scheme an operation names, e.g. RSA-PSS selected by the padding. */
    @Nonnull
    private static Optional<INode> schemeOf(@Nonnull INode operation) {
        return operation.getChildren().values().stream()
                .filter(IAlgorithm.class::isInstance)
                .filter(
                        child ->
                                child.is(Signature.class)
                                        || child.is(ProbabilisticSignatureScheme.class))
                .findFirst();
    }

    @Nonnull
    public static final IReorganizerRule MERGE_SIGNATURE_PARENT_AND_CHILD =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule("MERGE_SIGNATURE_PARENT_AND_CHILD")
                    .forNodeKind(Signature.class)
                    .withDetectionCondition(
                            (node, parent, roots) ->
                                    node.hasChildOfType(Signature.class).isPresent())
                    .perform(
                            UsualPerformActions.performMergeParentAndChildOfSameKind(
                                    Signature.class));

    @Nonnull
    public static final IReorganizerRule MERGE_SIGNATURE_WITH_PKE_UNDER_PRIVATE_KEY =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule("MERGE_SIGNATURE_WITH_PKE_UNDER_PRIVATE_KEY")
                    .forNodeKind(PrivateKey.class)
                    .withDetectionCondition(
                            (node, parent, roots) ->
                                    node.hasChildOfType(PublicKeyEncryption.class).isPresent()
                                            && node.hasChildOfType(Signature.class).isPresent())
                    .perform(
                            (node, parent, roots) -> {
                                final Optional<INode> pke =
                                        node.hasChildOfType(PublicKeyEncryption.class);
                                final Optional<INode> s = node.hasChildOfType(Signature.class);
                                if (pke.isPresent() && s.isPresent()) {
                                    pke.get()
                                            .hasChildOfType(EllipticCurve.class)
                                            .ifPresent(e -> s.get().put(e));
                                    node.removeChildOfType(pke.get().getKind());
                                }
                                return roots;
                            });

    @Nonnull
    public static final IReorganizerRule MOVE_PSS_FROM_UNDER_SIGN_FUNCTION_TO_UNDER_KEY =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule("MOVE_PSS_FROM_UNDER_SIGN_FUNCTION_TO_UNDER_KEY")
                    .forNodeKind(PrivateKey.class)
                    .withDetectionCondition(
                            (node, parent, roots) -> {
                                final Optional<INode> func = node.hasChildOfType(Sign.class);
                                return func.filter(
                                                iNode ->
                                                        node.hasChildOfType(
                                                                                PublicKeyEncryption
                                                                                        .class)
                                                                        .isPresent()
                                                                && iNode.hasChildOfType(
                                                                                ProbabilisticSignatureScheme
                                                                                        .class)
                                                                        .isPresent())
                                        .isPresent();
                            })
                    .perform(
                            (node, parent, roots) -> {
                                final Optional<INode> func = node.hasChildOfType(Sign.class);
                                if (func.isPresent()) {
                                    func.get()
                                            .hasChildOfType(ProbabilisticSignatureScheme.class)
                                            .ifPresent(
                                                    pss -> {
                                                        node.put(pss);
                                                        func.get()
                                                                .removeChildOfType(
                                                                        ProbabilisticSignatureScheme
                                                                                .class);
                                                    });
                                    // move as child of PSS
                                    func.get()
                                            .hasChildOfType(MessageDigest.class)
                                            .ifPresent(
                                                    digest -> {
                                                        node.hasChildOfType(
                                                                        ProbabilisticSignatureScheme
                                                                                .class)
                                                                .ifPresent(pss -> pss.put(digest));
                                                        func.get()
                                                                .removeChildOfType(
                                                                        MessageDigest.class);
                                                    });
                                    node.hasChildOfType(PublicKeyEncryption.class)
                                            .ifPresent(n -> node.removeChildOfType(n.getKind()));
                                }
                                return roots;
                            });

    @Nonnull
    public static final IReorganizerRule MAKE_RSA_TO_SIGNATURE =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule("MAKE_RSA_TO_SIGNATURE")
                    .forNodeKind(PrivateKey.class)
                    .withDetectionCondition(
                            (node, parent, roots) ->
                                    node.hasChildOfType(PublicKeyEncryption.class)
                                            .filter(
                                                    iNode ->
                                                            node.hasChildOfType(Sign.class)
                                                                            .isPresent()
                                                                    && iNode instanceof RSA)
                                            .isPresent())
                    .perform(
                            (node, parent, roots) -> {
                                final Optional<INode> pke =
                                        node.hasChildOfType(PublicKeyEncryption.class);
                                if (pke.isPresent() && pke.get() instanceof RSA rsa) {
                                    node.put(new RSA(Signature.class, rsa));
                                    node.removeChildOfType(pke.get().getKind());
                                }
                                return roots;
                            });

    @Nonnull
    public static IReorganizerRule moveNodesFromUnderFunctionalityUnderNode(
            @Nonnull Class<? extends Functionality> functionalityClazz,
            @Nonnull Class<? extends INode> underNodeClazz) {
        return new ReorganizerRuleBuilder()
                .createReorganizerRule("MOVE_NODES_FROM_UNDER_FUNCTIONALITY_UNDER_NODE")
                .forNodeKind(functionalityClazz)
                .withDetectionCondition(
                        (node, parent, roots) -> {
                            if (parent != null) {
                                return parent.hasChildOfType(underNodeClazz).isPresent();
                            }
                            return false;
                        })
                .perform(
                        (node, parent, roots) -> {
                            Optional.ofNullable(parent)
                                    .flatMap(p -> p.hasChildOfType(underNodeClazz))
                                    .ifPresent(
                                            n -> {
                                                for (Map.Entry<Class<? extends INode>, INode>
                                                        childKeyValue :
                                                                node.getChildren().entrySet()) {
                                                    n.put(childKeyValue.getValue());
                                                    node.removeChildOfType(childKeyValue.getKey());
                                                }
                                            });
                            return null;
                        });
    }

    @Nonnull
    public static IReorganizerRule moveFunctionalityUnderChildNode(
            @Nonnull Class<? extends Functionality> functionalityClazz,
            @Nonnull Class<? extends INode> childNodeClazz) {
        return new ReorganizerRuleBuilder()
                .createReorganizerRule("MOVE_FUNCTIONALITY_UNDER_CHILD_NODE")
                .forNodeKind(functionalityClazz)
                .withDetectionCondition(
                        (node, parent, roots) ->
                                parent == null && node.hasChildOfType(childNodeClazz).isPresent())
                .perform(
                        (node, parent, roots) -> {
                            Optional<INode> childOpt = node.hasChildOfType(childNodeClazz);
                            if (childOpt.isPresent()) {
                                INode child = childOpt.get();
                                // Remove the child from under the functionality
                                node.removeChildOfType(childNodeClazz);
                                // Put the functionality under the child
                                child.put(node);
                                // Replace the functionality with the child in roots
                                List<INode> newRoots = new LinkedList<>(roots);
                                newRoots.replaceAll(r -> r == node ? child : r);
                                return newRoots;
                            }
                            return roots;
                        });
    }

    @Nonnull
    public static IReorganizerRule moveNodesFromUnderFunctionalityUnderParent(
            @Nonnull Class<? extends Functionality> functionalityClazz,
            @Nonnull Class<? extends INode> parentNodeClazz) {
        return new ReorganizerRuleBuilder()
                .createReorganizerRule("MOVE_NODES_FROM_UNDER_FUNCTIONALITY_UNDER_PARENT")
                .forNodeKind(functionalityClazz)
                .withDetectionCondition(
                        (node, parent, roots) -> {
                            if (parent != null) {
                                return parent.is(parentNodeClazz);
                            }
                            return false;
                        })
                .perform(
                        (node, parent, roots) -> {
                            Optional.ofNullable(parent)
                                    .ifPresent(
                                            p -> {
                                                for (Map.Entry<Class<? extends INode>, INode>
                                                        childKeyValue :
                                                                node.getChildren().entrySet()) {
                                                    p.put(childKeyValue.getValue());
                                                    node.removeChildOfType(childKeyValue.getKey());
                                                }
                                            });
                            return null;
                        });
    }
}
