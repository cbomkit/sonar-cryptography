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

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.collections.ProtocolVersionSettings;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Resolves the range of versions a protocol uses from the versions set on it ({@link
 * ProtocolVersionSettings}): the versions disabled on it, e.g. by the {@code SSL_OP_NO_TLSv1}
 * option of an OpenSSL context, and its minimum and maximum versions. The settings add up, as
 * OpenSSL applies them together: the protocol uses the lowest run of versions that no setting
 * disables, e.g. with {@code SSL_OP_NO_TLSv1} and then {@code SSL_OP_NO_TLSv1_1} it uses TLS 1.2
 * and above, and with only {@code SSL_OP_NO_TLSv1_1} it uses TLS 1.0 only.
 *
 * <p>The protocol is given the lowest version of the range when its minimum is set or raised above
 * the lowest version, and the highest version of the range when its maximum is set or lowered below
 * the highest version: a second version is a copy of the tree of the protocol with that version, as
 * for a protocol configured with two versions. Each version is located where it is set, or where
 * the version next to it is disabled. A protocol whose method fixes its version keeps it.
 */
public final class ProtocolVersionReorganizer {

    private ProtocolVersionReorganizer() {
        // private
    }

    /**
     * The versions of a protocol family, lowest first, and the lowest version used by default: SSL
     * 3.0 is not built into OpenSSL by default since 1.1.0, so it is used only when it is set.
     */
    private record Family(@Nonnull String prefix, @Nonnull List<String> versions, int lowest) {

        boolean includes(@Nonnull String version) {
            return familyOf(version) == this;
        }
    }

    private static final Family DTLS = new Family("DTLS", List.of("DTLSv1.0", "DTLSv1.2"), 0);

    private static final Family TLS_FAMILY =
            new Family("TLS", List.of("SSLv3.0", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"), 1);

    private static final List<Class<? extends ProtocolVersionSettings>> SETTINGS =
            List.of(
                    ProtocolVersionSettings.Disabled.class,
                    ProtocolVersionSettings.Minimum.class,
                    ProtocolVersionSettings.Maximum.class);

    /**
     * Resolves the versions set on a protocol of the given kind, e.g. an OpenSSL context reported
     * as a {@link TLS} node, to the bounds of the range of versions it uses.
     */
    @Nonnull
    public static IReorganizerRule resolveVersionsSetOn(
            @Nonnull Class<? extends INode> protocolKind) {
        return new ReorganizerRuleBuilder()
                .createReorganizerRule()
                .forNodeKind(protocolKind)
                .withDetectionCondition((node, parent, roots) -> !settingsOf(node).isEmpty())
                .perform(
                        (node, parent, roots) -> {
                            final List<ProtocolVersionSettings> settings = settingsOf(node);
                            settings.forEach(setting -> node.removeChildOfType(setting.getKind()));
                            if (hasFixedVersion(node)) {
                                return roots;
                            }
                            // a method negotiating the version, given to the context after its
                            // creation, is the protocol the versions bound
                            final INode protocol = node.hasChildOfType(TLS.class).orElse(node);
                            return withVersions(protocol, resolve(settings), roots);
                        });
    }

    /**
     * Resolves the versions set on a protocol created elsewhere, e.g. by {@code
     * SSL_CTX_set_options} on a context given to a function, found on their own: each setting found
     * as a root is replaced by the bounds of the range of versions it leaves.
     */
    @Nonnull
    public static List<IReorganizerRule> resolveVersionsSetOnTheirOwn() {
        return SETTINGS.stream()
                .map(
                        kind ->
                                new ReorganizerRuleBuilder()
                                        .createReorganizerRule()
                                        .forNodeKind(kind)
                                        .withDetectionCondition(
                                                (node, parent, roots) -> parent == null)
                                        .perform(
                                                (node, parent, roots) -> {
                                                    final List<ProtocolVersionSettings> settings =
                                                            new ArrayList<>();
                                                    settings.add((ProtocolVersionSettings) node);
                                                    settings.addAll(settingsOf(node));
                                                    final List<INode> result = new ArrayList<>();
                                                    for (INode root : roots) {
                                                        if (root == node) {
                                                            result.addAll(resolve(settings));
                                                        } else {
                                                            result.add(root);
                                                        }
                                                    }
                                                    return result;
                                                }))
                .toList();
    }

    @Nonnull
    private static List<ProtocolVersionSettings> settingsOf(@Nonnull INode node) {
        return SETTINGS.stream()
                .map(node::hasChildOfType)
                .flatMap(Optional::stream)
                .map(ProtocolVersionSettings.class::cast)
                .toList();
    }

    /** Whether the protocol, or the method given to it, is of one version, e.g. TLS 1.2 only. */
    private static boolean hasFixedVersion(@Nonnull INode node) {
        return node.hasChildOfType(Version.class).isPresent()
                || node.hasChildOfType(TLS.class)
                        .flatMap(method -> method.hasChildOfType(Version.class))
                        .isPresent();
    }

    /**
     * The roots, the protocol given the first version, and a copy of the tree of the protocol with
     * each other version.
     */
    @Nonnull
    private static List<INode> withVersions(
            @Nonnull INode protocol, @Nonnull List<INode> versions, @Nonnull List<INode> roots) {
        if (versions.isEmpty()) {
            return roots;
        }
        final List<INode> result = new ArrayList<>(roots);
        for (INode version : versions.subList(1, versions.size())) {
            result.add(copyWith(roots, protocol, version));
        }
        protocol.put(versions.get(0));
        return result;
    }

    /**
     * A copy of the root holding the protocol, with the version put in the copy of the protocol.
     */
    @Nonnull
    private static INode copyWith(
            @Nonnull List<INode> roots, @Nonnull INode protocol, @Nonnull INode version) {
        for (INode root : roots) {
            final Optional<List<Class<? extends INode>>> path = pathTo(root, protocol);
            if (path.isPresent()) {
                final INode copy = root.deepCopy();
                INode node = copy;
                for (Class<? extends INode> kind : path.get()) {
                    node = node.getChildren().get(kind);
                }
                node.put(version);
                return copy;
            }
        }
        final INode copy = protocol.deepCopy();
        copy.put(version);
        return copy;
    }

    /** The kinds of the children leading from the node to the target, when the target is below. */
    @Nonnull
    private static Optional<List<Class<? extends INode>>> pathTo(
            @Nonnull INode node, @Nonnull INode target) {
        if (node == target) {
            return Optional.of(new ArrayList<>());
        }
        for (Map.Entry<Class<? extends INode>, INode> child : node.getChildren().entrySet()) {
            final Optional<List<Class<? extends INode>>> below = pathTo(child.getValue(), target);
            if (below.isPresent()) {
                below.get().add(0, child.getKey());
                return below;
            }
        }
        return Optional.empty();
    }

    /** The bounds of the range of versions left by the settings, for each family they set. */
    @Nonnull
    private static List<INode> resolve(@Nonnull List<ProtocolVersionSettings> settings) {
        return Stream.of(TLS_FAMILY, DTLS).flatMap(family -> resolve(family, settings)).toList();
    }

    @Nonnull
    private static Stream<INode> resolve(
            @Nonnull Family family, @Nonnull List<ProtocolVersionSettings> settings) {
        final List<TLS> disabled =
                versionsOf(ProtocolVersionSettings.Disabled.class, family, settings);
        final List<TLS> minimums =
                versionsOf(ProtocolVersionSettings.Minimum.class, family, settings);
        final List<TLS> maximums =
                versionsOf(ProtocolVersionSettings.Maximum.class, family, settings);
        if (disabled.isEmpty() && minimums.isEmpty() && maximums.isEmpty()) {
            return Stream.empty();
        }
        final List<String> versions = family.versions();
        final Set<Integer> off = new HashSet<>();
        disabled.forEach(version -> off.add(versions.indexOf(version.asString())));
        // the versions below the default lowest one are used only when they are set
        final boolean lowerVersionSet =
                Stream.concat(minimums.stream(), maximums.stream())
                        .anyMatch(
                                version -> versions.indexOf(version.asString()) < family.lowest());
        if (!lowerVersionSet) {
            for (int i = 0; i < family.lowest(); i++) {
                off.add(i);
            }
        }
        for (TLS minimum : minimums) {
            for (int i = 0; i < versions.indexOf(minimum.asString()); i++) {
                off.add(i);
            }
        }
        for (TLS maximum : maximums) {
            for (int i = versions.indexOf(maximum.asString()) + 1; i < versions.size(); i++) {
                off.add(i);
            }
        }
        int lowest = 0;
        while (lowest < versions.size() && off.contains(lowest)) {
            lowest++;
        }
        if (lowest == versions.size()) {
            return Stream.empty();
        }
        int highest = lowest;
        while (highest + 1 < versions.size() && !off.contains(highest + 1)) {
            highest++;
        }

        final List<INode> bounds = new ArrayList<>(2);
        final boolean minimumBound = lowest > family.lowest() || !minimums.isEmpty();
        if (minimumBound) {
            final String version = versions.get(lowest);
            final Optional<DetectionLocation> disabledBelow =
                    lowest > 0 ? locationOf(versions.get(lowest - 1), disabled) : Optional.empty();
            bounds.add(
                    version(
                            version,
                            locationOf(version, minimums)
                                    .or(() -> disabledBelow)
                                    .orElseGet(() -> firstLocation(settings))));
        }
        final boolean maximumBound = highest < versions.size() - 1 || !maximums.isEmpty();
        if (maximumBound && !(minimumBound && highest == lowest)) {
            final String version = versions.get(highest);
            final Optional<DetectionLocation> disabledAbove =
                    highest + 1 < versions.size()
                            ? locationOf(versions.get(highest + 1), disabled)
                            : Optional.empty();
            bounds.add(
                    version(
                            version,
                            locationOf(version, maximums)
                                    .or(() -> disabledAbove)
                                    .orElseGet(() -> firstLocation(settings))));
        }
        return bounds.stream();
    }

    /** The versions of a family set by the settings of a kind. */
    @Nonnull
    private static List<TLS> versionsOf(
            @Nonnull Class<? extends ProtocolVersionSettings> kind,
            @Nonnull Family family,
            @Nonnull List<ProtocolVersionSettings> settings) {
        return settings.stream()
                .filter(setting -> setting.is(kind))
                .flatMap(setting -> setting.getCollection().stream())
                .filter(TLS.class::isInstance)
                .map(TLS.class::cast)
                .filter(version -> family.includes(version.asString()))
                .toList();
    }

    @Nonnull
    private static Family familyOf(@Nonnull String version) {
        return version.startsWith(DTLS.prefix()) ? DTLS : TLS_FAMILY;
    }

    @Nonnull
    private static Optional<DetectionLocation> locationOf(
            @Nonnull String version, @Nonnull List<TLS> versions) {
        return versions.stream()
                .filter(node -> node.asString().equals(version))
                .map(TLS::getDetectionContext)
                .findFirst();
    }

    @Nonnull
    private static DetectionLocation firstLocation(
            @Nonnull List<ProtocolVersionSettings> settings) {
        return settings.stream()
                .flatMap(setting -> setting.getCollection().stream())
                .filter(TLS.class::isInstance)
                .map(TLS.class::cast)
                .map(TLS::getDetectionContext)
                .findFirst()
                .orElseThrow();
    }

    /** The protocol node of a version, e.g. {@code TLSv1.2} with its version {@code 1.2}. */
    @Nonnull
    private static INode version(@Nonnull String name, @Nonnull DetectionLocation location) {
        return new TLS(name, new Version(name.substring(name.indexOf('v') + 1), location));
    }
}
