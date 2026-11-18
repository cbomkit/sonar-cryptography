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
package com.ibm.output.cyclondx;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.IAsset;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.IProperty;
import com.ibm.mapper.model.InitializationVectorLength;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.NonceLength;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.PasswordLength;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.functionality.Decapsulate;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.Functionality;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.output.Constants;
import com.ibm.output.IOutputFile;
import com.ibm.output.cyclondx.builder.AlgorithmComponentBuilder;
import com.ibm.output.cyclondx.builder.ProtocolComponentBuilder;
import com.ibm.output.cyclondx.builder.RelatedCryptoMaterialComponentBuilder;
import com.ibm.output.util.Utils;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.commons.io.FileUtils;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.OrganizationalEntity;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.Service;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.ProtocolProperties;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.cyclonedx.model.metadata.ToolInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CBOMOutputFile implements IOutputFile {
    private static final Logger LOGGER = LoggerFactory.getLogger(CBOMOutputFile.class);
    private static final Version schema = Version.VERSION_16;

    @Nonnull private final Map<String, Component> components;
    @Nonnull private final Map<String, Dependency> dependencies;

    /**
     * Per component id, the distinct values of each detection property seen over all occurrences
     * merged into that component (see {@link DetectionProperties}).
     */
    @Nonnull private final Map<String, Map<String, SortedSet<String>>> componentProperties;

    public CBOMOutputFile() {
        this.components = new HashMap<>();
        this.dependencies = new HashMap<>();
        this.componentProperties = new HashMap<>();
    }

    @Override
    public void add(@Nonnull List<INode> nodes) {
        add(null, nodes);
    }

    private void add(@Nullable final String parentBomRef, @Nonnull List<INode> nodes) {
        nodes.forEach(
                node -> {
                    // switch for asset
                    if (node instanceof Algorithm algorithm) {
                        createAlgorithmComponent(parentBomRef, algorithm);
                    } else if (node instanceof Key key) {
                        createKeyComponent(parentBomRef, key);
                    } else if (node instanceof Protocol protocol) {
                        createProtocolComponent(parentBomRef, protocol);
                    } else if (node instanceof CipherSuite cipherSuite) {
                        createCipherSuiteComponent(parentBomRef, cipherSuite);
                    } else if (node instanceof SaltLength
                            || node instanceof PasswordLength
                            || node instanceof InitializationVectorLength
                            || node instanceof NonceLength) {
                        final IProperty property = (IProperty) node;
                        createRelatedCryptoMaterialComponent(parentBomRef, property);
                    } else if (node.hasChildren()) {
                        add(parentBomRef, node.getChildren().values().stream().toList());
                    }
                });
    }

    @Nullable private String createAlgorithmComponent(
            @Nullable String parentBomRef, @Nonnull Algorithm node) {
        Map<Class<? extends INode>, INode> children = node.getChildren();
        Component algorithm =
                AlgorithmComponentBuilder.create()
                        .algorithm(node)
                        .mode(children.get(Mode.class))
                        .curve(children.get(EllipticCurve.class))
                        .parameterSetIdentifier(
                                Utils.oneOf(
                                        children.get(KeyLength.class),
                                        children.get(DigestSize.class),
                                        children.get(BlockSize.class),
                                        children.get(ParameterSetIdentifier.class)))
                        .padding(Utils.oneOf(children.get(OAEP.class), children.get(Padding.class)))
                        .cryptoFunctions(
                                Utils.allExisting(
                                        children.get(Decapsulate.class),
                                        children.get(Decrypt.class),
                                        children.get(Digest.class),
                                        children.get(Encapsulate.class),
                                        children.get(Encrypt.class),
                                        children.get(Generate.class),
                                        children.get(KeyDerivation.class),
                                        children.get(KeyGeneration.class),
                                        children.get(Sign.class),
                                        children.get(Tag.class),
                                        children.get(Verify.class)))
                        .primitive(node)
                        .occurrences(createOccurrenceForm(node.getDetectionContext()))
                        .oid(children.get(Oid.class))
                        .build();
        final Optional<String> optionalId = getIdentifierFunction().apply(algorithm);
        if (optionalId.isEmpty()) {
            return null;
        }
        addComponentAndDependencies(
                algorithm, optionalId.get(), parentBomRef, node, node.getDetectionContext());
        return this.components.get(optionalId.get()).getBomRef();
    }

    private void createKeyComponent(@Nullable String parentBomRef, @Nonnull Key node) {
        // if functionality nodes are placed under the key node,
        // they will be moved under the corresponding primitive node.
        Utils.pushNodesDownToFirstMatch(node, IPrimitive.getKinds(), Functionality.getKinds());
        // if a key length is defined under the key node, this function makes sure that the
        // underlying primitive
        // will get the same key length associated.
        Utils.pushNodesDownToFirstMatch(
                node, IPrimitive.getKinds(), List.of(KeyLength.class), false);

        createRelatedCryptoMaterialComponent(parentBomRef, node);
    }

    private void createProtocolComponent(@Nullable String parentBomRef, @Nonnull Protocol node) {
        Map<Class<? extends INode>, INode> children = node.getChildren();
        Component protocol =
                ProtocolComponentBuilder.create(this::createAlgorithmComponent)
                        .name(node)
                        .type(node)
                        .version(children.get(com.ibm.mapper.model.Version.class))
                        .cipherSuites(children.get(CipherSuiteCollection.class))
                        .occurrences(createOccurrenceForm(node.getDetectionContext()))
                        .build();
        final Optional<String> optionalId = getIdentifierFunction().apply(protocol);
        if (optionalId.isEmpty()) {
            return;
        }
        addComponentAndDependencies(
                protocol, optionalId.get(), parentBomRef, node, node.getDetectionContext());

        // the component kept under this name: the one just built, or the one it was merged into
        final Component kept = this.components.get(optionalId.get());
        Dependency protocolDependency = dependencies.get(kept.getBomRef());
        if (protocolDependency != null) {
            List<String> cryptoRefs =
                    protocolDependency.getDependencies().stream().map(Dependency::getRef).toList();
            kept.getCryptoProperties().getProtocolProperties().setCryptoRefArray(cryptoRefs);
        }
    }

    private void createCipherSuiteComponent(
            @Nullable String parentBomRef, @Nonnull CipherSuite node) {
        final TLS tls = new TLS(node.getDetectionContext());
        Component protocol =
                ProtocolComponentBuilder.create(this::createAlgorithmComponent)
                        .name(tls)
                        .type(tls)
                        .version(null)
                        .cipherSuites(new CipherSuiteCollection(List.of(node)))
                        .occurrences(createOccurrenceForm(node.getDetectionContext()))
                        .build();
        final Optional<String> optionalId = getIdentifierFunction().apply(protocol);
        if (optionalId.isEmpty()) {
            return;
        }
        addComponentAndDependencies(
                protocol, optionalId.get(), parentBomRef, node, node.getDetectionContext());
    }

    private void createRelatedCryptoMaterialComponent(
            @Nullable String parentBomRef, @Nonnull INode node) {
        Map<Class<? extends INode>, INode> children = node.getChildren();
        final DetectionLocation detectionLocation;
        if (node instanceof IProperty property) {
            detectionLocation = property.getDetectionContext();
        } else if (node instanceof IAsset iAsset) {
            detectionLocation = iAsset.getDetectionContext();
        } else {
            return;
        }
        Component rcm =
                RelatedCryptoMaterialComponentBuilder.create()
                        .name(node)
                        .size(Utils.oneOf(children.get(KeyLength.class), node))
                        .type(node)
                        .occurrences(createOccurrenceForm(detectionLocation))
                        .build();
        final Optional<String> optionalId = getIdentifierFunction().apply(rcm);
        if (optionalId.isEmpty()) {
            return;
        }
        addComponentAndDependencies(rcm, optionalId.get(), parentBomRef, node, detectionLocation);
    }

    /**
     * Merges one component into another when both carry the same identity.
     *
     * <p>Two detections become the same component when they print the same name, and the name holds
     * only part of what a detection knows ({@code Algorithm.asString}). So two call sites can share
     * an identity while differing in everything the name leaves out. The clearest case is a cipher
     * created twice from the same string, once to encrypt and once to decrypt: the direction is not
     * part of the name, both land here, and until this merge existed only the component found first
     * survived and so the second direction was dropped and the inventory claimed the code never
     * encrypts.
     *
     * <p>What is merged is deliberately narrow: the list-valued properties, and a whole
     * sub-property object where the kept component has none at all. A list is safe to union because
     * the component stands for all of its occurrences together, and collectively they do perform
     * every function any of them performs.
     *
     * <p>Single-valued properties are deliberately <em>not</em> filled in from the other component,
     * even when the kept one has none. They describe one call site's configuration, and a component
     * covering several would then state something about occurrences that never said it.
     */
    private static void mergeCryptoProperties(
            @Nonnull Component kept, @Nonnull Component incoming) {
        final CryptoProperties from = incoming.getCryptoProperties();
        if (from == null) {
            return;
        }
        if (kept.getCryptoProperties() == null) {
            kept.setCryptoProperties(from);
            return;
        }
        final CryptoProperties into = kept.getCryptoProperties();

        final AlgorithmProperties source = from.getAlgorithmProperties();
        if (source == null) {
            return;
        }
        if (into.getAlgorithmProperties() == null) {
            into.setAlgorithmProperties(source);
            return;
        }
        final AlgorithmProperties target = into.getAlgorithmProperties();
        // Only ever written when the union has something in it, so a property neither component
        // stated is left exactly as it was rather than being replaced by null or an empty list.
        replaceIfNotEmpty(
                target::setCryptoFunctions,
                union(target.getCryptoFunctions(), source.getCryptoFunctions()));
        replaceIfNotEmpty(
                target::setCertificationLevel,
                union(target.getCertificationLevel(), source.getCertificationLevel()));
    }

    private static <T> void replaceIfNotEmpty(
            @Nonnull Consumer<List<T>> setter, @Nullable List<T> value) {
        if (value != null && !value.isEmpty()) {
            setter.accept(value);
        }
    }

    /**
     * Union of two lists, keeping the order in which values were first seen and dropping repeats.
     * Returns {@code null} for two empty inputs so that a property nobody stated stays absent from
     * the CBOM rather than appearing as an empty list.
     */
    @Nullable private static <T> List<T> union(@Nullable List<T> first, @Nullable List<T> second) {
        final List<T> result = new ArrayList<>();
        Stream.concat(
                        first == null ? Stream.empty() : first.stream(),
                        second == null ? Stream.empty() : second.stream())
                .filter(value -> !result.contains(value))
                .forEach(result::add);
        return result.isEmpty() ? null : result;
    }

    private static void mergeOccurrences(@Nonnull Component kept, @Nonnull Component incoming) {
        if (incoming.getEvidence() == null) {
            return;
        }
        if (kept.getEvidence() == null) {
            kept.setEvidence(incoming.getEvidence());
            return;
        }
        final List<Occurrence> merged =
                Stream.concat(
                                kept.getEvidence().getOccurrences().stream(),
                                incoming.getEvidence().getOccurrences().stream())
                        .filter(
                                com.ibm.output.cyclondx.builder.Utils.distinctByKey(
                                        o ->
                                                o.getLocation()
                                                        + " "
                                                        + o.getLine()
                                                        + " "
                                                        + o.getOffset()
                                                        + " "
                                                        + o.getAdditionalContext()
                                                        + " "))
                        .toList();
        kept.getEvidence().setOccurrences(merged);
    }

    private void addComponentAndDependencies(
            @Nonnull final Component component,
            @Nonnull String componentId,
            @Nullable String parentBomRef,
            @Nonnull INode node,
            @Nonnull DetectionLocation detectionLocation) {
        if (components.get(componentId) == null) {
            this.components.putIfAbsent(componentId, component);
        } else {
            this.components.computeIfPresent(
                    componentId,
                    (id, kept) -> {
                        mergeOccurrences(kept, component);
                        mergeCryptoProperties(kept, component);
                        return kept;
                    });
            final Component kept = this.components.get(componentId);
            if (kept != component) {
                mergeDiscarded(kept, component);
            }
        }

        Component componentIdentify = this.components.get(componentId);
        mergeProperties(componentId, componentIdentify, detectionLocation);
        // a protocol whose cipher suite is reported as that same protocol (a TLS suite under a TLS)
        // must not depend on itself
        if (parentBomRef != null && !parentBomRef.equals(componentIdentify.getBomRef())) {
            Dependency newDependency = new Dependency(componentIdentify.getBomRef());
            if (dependencies.get(parentBomRef) == null) {
                Dependency parent = new Dependency(parentBomRef);
                parent.addDependency(newDependency);
                this.dependencies.putIfAbsent(parentBomRef, parent);
            } else {
                this.dependencies.computeIfPresent(
                        parentBomRef,
                        (s, d) -> {
                            d.addDependency(newDependency);
                            return d;
                        });
            }
        }

        if (node.hasChildren()) {
            add(componentIdentify.getBomRef(), node.getChildren().values().stream().toList());
        }
    }

    /**
     * {@code discarded} was built for a name that already has a component, {@code kept}, and only
     * its occurrences were merged. Builders that register dependencies while building (a protocol's
     * cipher-suite algorithms) did so under the discarded component's bom-ref, which is in no
     * component: move those dependencies to {@code kept}, and keep the cipher suites the discarded
     * protocol listed (by name, first one wins), so neither a dangling {@code ref} nor a lost suite
     * remains.
     */
    private void mergeDiscarded(@Nonnull Component kept, @Nonnull Component discarded) {
        final Dependency orphan = this.dependencies.remove(discarded.getBomRef());
        if (orphan != null && orphan.getDependencies() != null) {
            for (Dependency dependency : orphan.getDependencies()) {
                if (dependency.getRef().equals(kept.getBomRef())) {
                    continue;
                }
                final Dependency target =
                        this.dependencies.computeIfAbsent(kept.getBomRef(), Dependency::new);
                target.addDependency(new Dependency(dependency.getRef()));
            }
        }
        if (kept.getCryptoProperties() == null || discarded.getCryptoProperties() == null) {
            return;
        }
        final ProtocolProperties keptProtocol = kept.getCryptoProperties().getProtocolProperties();
        final ProtocolProperties discardedProtocol =
                discarded.getCryptoProperties().getProtocolProperties();
        if (keptProtocol == null
                || discardedProtocol == null
                || discardedProtocol.getCipherSuites() == null) {
            return;
        }
        final List<org.cyclonedx.model.component.crypto.CipherSuite> suites =
                keptProtocol.getCipherSuites() == null
                        ? new ArrayList<>()
                        : new ArrayList<>(keptProtocol.getCipherSuites());
        for (org.cyclonedx.model.component.crypto.CipherSuite suite :
                discardedProtocol.getCipherSuites()) {
            if (suites.stream().noneMatch(s -> Objects.equals(s.getName(), suite.getName()))) {
                suites.add(suite);
            }
        }
        keptProtocol.setCipherSuites(suites);
        if (keptProtocol.getCryptoRefArray() != null) {
            final Dependency keptDependency = this.dependencies.get(kept.getBomRef());
            if (keptDependency != null) {
                keptProtocol.setCryptoRefArray(
                        keptDependency.getDependencies().stream().map(Dependency::getRef).toList());
            }
        }
    }

    /**
     * Adds the location's detection properties to the value sets of the component and rewrites the
     * component's {@code properties}: one {@link Property} per key, its value the sorted distinct
     * values joined by {@link DetectionProperties#VALUE_SEPARATOR}. A component none of whose
     * occurrences has properties gets no {@code properties} at all.
     */
    private void mergeProperties(
            @Nonnull String componentId,
            @Nonnull Component component,
            @Nonnull DetectionLocation detectionLocation) {
        if (detectionLocation.properties().isEmpty()) {
            return;
        }
        final Map<String, SortedSet<String>> values =
                this.componentProperties.computeIfAbsent(componentId, id -> new TreeMap<>());
        detectionLocation
                .properties()
                .forEach(
                        (key, value) -> {
                            if (DetectionProperties.COMPONENT_FACTS.contains(key)) {
                                values.computeIfAbsent(key, k -> new TreeSet<>()).add(value);
                            }
                        });
        if (values.isEmpty()) {
            return;
        }
        final List<Property> properties = new ArrayList<>();
        values.forEach(
                (key, set) ->
                        properties.add(
                                new Property(
                                        key,
                                        String.join(DetectionProperties.VALUE_SEPARATOR, set))));
        component.setProperties(properties);
    }

    @Nonnull
    public Bom getBom() {
        final Bom bom = new Bom();
        bom.setSerialNumber("urn:uuid:" + UUID.randomUUID());
        // add metadata
        final Metadata metadata = new Metadata();
        metadata.setTimestamp(new Date());
        // add scanner to metadata
        final ToolInformation scannerInfo = new ToolInformation();
        final Service scannerService = new Service();
        scannerService.setName(Constants.SCANNER_NAME);
        final OrganizationalEntity organization = new OrganizationalEntity();
        organization.setName(Constants.SCANNER_VENDOR);
        scannerService.setProvider(organization);
        try {
            final Properties properties = new Properties();
            properties.load(
                    this.getClass().getClassLoader().getResourceAsStream("plugin.properties"));
            scannerService.setVersion(properties.getProperty("plugin.version"));
        } catch (Exception e) {
            scannerService.setVersion("0.0.0");
        }
        scannerInfo.setServices(List.of(scannerService));
        metadata.setToolChoice(scannerInfo);
        bom.setMetadata(metadata);
        bom.setComponents(new ArrayList<>(this.components.values()));
        bom.setDependencies(new ArrayList<>(this.dependencies.values()));
        return bom;
    }

    @Override
    public void saveTo(@Nonnull File file) {
        final Bom bom = getBom();
        final BomJsonGenerator bomGenerator = BomGeneratorFactory.createJson(schema, bom);
        try {
            final String bomString = bomGenerator.toJsonString();
            FileUtils.write(file, bomString, StandardCharsets.UTF_8, false);
        } catch (IOException e) {
            LOGGER.error("Could not write CBOM file: {}", e.getMessage());
        } catch (GeneratorException e) {
            LOGGER.error("Could not generate CBOM: {}", e.getMessage());
        }
    }

    @Nonnull
    private Function<Component, Optional<String>> getIdentifierFunction() {
        return (component -> Optional.ofNullable(component.getName()));
    }

    @Nonnull
    private Occurrence createOccurrenceForm(@Nonnull DetectionLocation detectionLocation) {
        final Occurrence occurrence = new Occurrence();
        occurrence.setLocation(detectionLocation.filePath());
        occurrence.setLine(detectionLocation.lineNumber());
        occurrence.setOffset(detectionLocation.offSet());
        final String keyword =
                detectionLocation.keywords().isEmpty() ? null : detectionLocation.keywords().get(0);
        final String facts = DetectionProperties.occurrenceContext(detectionLocation.properties());
        if (facts.isEmpty()) {
            if (keyword != null) {
                occurrence.setAdditionalContext(keyword);
            }
        } else if (keyword == null
                || keyword.equals(
                        detectionLocation.properties().get(DetectionProperties.RULE_ID))) {
            // the detections translator passes the rule id as keyword; it is already in the facts
            occurrence.setAdditionalContext(facts);
        } else {
            occurrence.setAdditionalContext(keyword + "; " + facts);
        }
        return occurrence;
    }
}
