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
package com.ibm.output.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.mapper.model.AlgorithmFamily;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.MLDSA;
import com.ibm.mapper.model.algorithms.MLKEM;
import com.ibm.mapper.model.algorithms.RFC3211Wrap;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAKEM;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.Scrypt;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.curves.Brainpoolp256r1;
import com.ibm.mapper.model.curves.Curve25519;
import com.ibm.mapper.model.curves.Edwards25519;
import com.ibm.mapper.model.curves.Secp256r1;
import com.ibm.mapper.model.curves.Sect163k1;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.model.protocol.IPSec;
import com.ibm.output.cyclondx.CBOMOutputFile;
import com.ibm.output.cyclondx.builder.CycloneDxRegistry;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.cyclonedx.Version;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.ProtocolProperties;
import org.cyclonedx.model.component.crypto.RelatedCryptographicAsset;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** CycloneDX 1.7 specific output: registry identifiers, deprecated fields and relationships. */
class CycloneDx17Test extends TestBase {

    private static AlgorithmProperties algorithmProperties(Bom bom, String name) {
        return bom.getComponents().stream()
                .filter(c -> name.equals(c.getName()))
                .findFirst()
                .orElseThrow()
                .getCryptoProperties()
                .getAlgorithmProperties();
    }

    private static String familyOf(Bom bom) {
        assertThat(bom.getComponents()).isNotEmpty();
        return bom.getComponents()
                .get(0)
                .getCryptoProperties()
                .getAlgorithmProperties()
                .getAlgorithmFamily();
    }

    @Test
    void rsaFamilyFollowsKindAndPadding() {
        this.assertsNode(
                () -> new RSA(detectionLocation),
                bom -> assertThat(familyOf(bom)).isEqualTo("RSAES-PKCS1"));
        this.assertsNode(
                () -> {
                    final RSA rsa = new RSA(PublicKeyEncryption.class, detectionLocation);
                    rsa.put(new OAEP(detectionLocation));
                    return rsa;
                },
                bom -> assertThat(familyOf(bom)).isEqualTo("RSAES-OAEP"));
        this.assertsNode(
                () -> new RSA(Signature.class, detectionLocation),
                bom -> assertThat(familyOf(bom)).isEqualTo("RSASSA-PKCS1"));
        this.assertsNode(
                () -> new RSAssaPSS(detectionLocation),
                bom -> assertThat(familyOf(bom)).isEqualTo("RSASSA-PSS"));
        this.assertsNode(
                () -> new RSAKEM(detectionLocation), bom -> assertThat(familyOf(bom)).isNull());
    }

    @Test
    void ellipticCurveAlgorithmFamilyFollowsCurveAndKind() {
        this.assertsNode(
                () -> new EllipticCurveAlgorithm(new Secp256r1(detectionLocation)),
                bom -> assertThat(familyOf(bom)).isNull());
        this.assertsNode(
                () ->
                        new EllipticCurveAlgorithm(
                                Signature.class,
                                new EllipticCurveAlgorithm(new Secp256r1(detectionLocation))),
                bom -> assertThat(familyOf(bom)).isEqualTo("ECDSA"));
        this.assertsNode(
                () ->
                        new EllipticCurveAlgorithm(
                                KeyAgreement.class,
                                new EllipticCurveAlgorithm(new Secp256r1(detectionLocation))),
                bom -> assertThat(familyOf(bom)).isEqualTo("ECDH"));
        this.assertsNode(
                () -> new EllipticCurveAlgorithm(new Curve25519(detectionLocation)),
                bom -> assertThat(familyOf(bom)).isEqualTo("ECDH"));
        this.assertsNode(
                () -> new EllipticCurveAlgorithm(new Edwards25519(detectionLocation)),
                bom -> assertThat(familyOf(bom)).isEqualTo("EdDSA"));
    }

    @Test
    void familiesOfOtherAlgorithms() {
        this.assertsNode(
                () -> new X25519(detectionLocation),
                bom -> assertThat(familyOf(bom)).isEqualTo("ECDH"));
        this.assertsNode(
                () -> new SHA(detectionLocation),
                bom -> assertThat(familyOf(bom)).isEqualTo("SHA-1"));
        this.assertsNode(
                () -> new SHA2(224, detectionLocation),
                bom -> assertThat(familyOf(bom)).isEqualTo("SHA-2"));
        this.assertsNode(
                () -> new SHA3(detectionLocation),
                bom -> assertThat(familyOf(bom)).isEqualTo("SHA-3"));
        this.assertsNode(
                () -> new SHA3(256, detectionLocation),
                bom -> assertThat(familyOf(bom)).isEqualTo("SHA-3"));
        this.assertsNode(
                () -> new MLKEM(768, detectionLocation),
                bom -> assertThat(familyOf(bom)).isEqualTo("ML-KEM"));
        this.assertsNode(
                () -> new MLDSA(65, detectionLocation),
                bom -> assertThat(familyOf(bom)).isEqualTo("ML-DSA"));
        this.assertsNode(
                () -> new Scrypt(detectionLocation),
                bom -> assertThat(familyOf(bom)).isEqualTo("scrypt"));
        this.assertsNode(
                () -> new AES(128, new CBC(detectionLocation), detectionLocation),
                bom -> assertThat(familyOf(bom)).isEqualTo("AES"));
    }

    @Test
    void curvesAreRegistryIdentifiersAndDeprecatedCurveIsKept() {
        this.assertsNode(
                () -> new EllipticCurveAlgorithm(new Secp256r1(detectionLocation)),
                bom -> {
                    final AlgorithmProperties properties = algorithmProperties(bom, "EC-secp256r1");
                    assertThat(properties.getEllipticCurve()).isEqualTo("nist/P-256");
                    assertThat(properties.getCurve()).isEqualTo("secp256r1");
                });
        this.assertsNode(
                () -> new EllipticCurveAlgorithm(new Sect163k1(detectionLocation)),
                bom ->
                        assertThat(algorithmProperties(bom, "EC-sect163k1").getEllipticCurve())
                                .isEqualTo("secg/sect163k1"));
        this.assertsNode(
                () -> new EllipticCurveAlgorithm(new Brainpoolp256r1(detectionLocation)),
                bom ->
                        assertThat(
                                        algorithmProperties(bom, "EC-Brainpoolp256r1")
                                                .getEllipticCurve())
                                .isEqualTo("brainpool/brainpoolP256r1"));
    }

    @Test
    void unknownCurveIsNeverEmittedAsRegistryIdentifier() {
        this.assertsNode(
                () ->
                        new EllipticCurveAlgorithm(
                                new com.ibm.mapper.model.EllipticCurve(
                                        "not-a-curve", detectionLocation)),
                bom -> {
                    final AlgorithmProperties properties =
                            algorithmProperties(bom, "EC-not-a-curve");
                    assertThat(properties.getEllipticCurve()).isNull();
                    assertThat(properties.getCurve()).isEqualTo("not-a-curve");
                });
    }

    @Test
    void keyWrapIsSerializedAsKeyWrapPrimitive() {
        this.assertsNode(
                () -> new RFC3211Wrap(detectionLocation),
                bom -> {
                    assertThat(algorithmProperties(bom, "RFC 3211").getPrimitive())
                            .isEqualTo(Primitive.OTHER);
                    assertThat(lastJson).contains("\"primitive\" : \"key-wrap\"");
                });
    }

    @Test
    void otherPrimitivesAreStillSerialized() {
        this.assertsNode(
                () -> new SHA2(256, detectionLocation),
                bom -> assertThat(lastJson).contains("\"primitive\" : \"hash\""));
    }

    @Test
    void protocolListsAssetsOfAllOccurrences() {
        this.assertsNodes(
                () -> {
                    final IPSec first = new IPSec(detectionLocation);
                    first.put(new AES(128, new CBC(detectionLocation), detectionLocation));
                    final IPSec second = new IPSec(detectionLocation);
                    second.put(new RSA(detectionLocation));
                    return List.of(first, second);
                },
                bom -> {
                    final Component ipsec =
                            bom.getComponents().stream()
                                    .filter(c -> "IPSec".equals(c.getName()))
                                    .findFirst()
                                    .orElseThrow();
                    final ProtocolProperties properties =
                            ipsec.getCryptoProperties().getProtocolProperties();
                    assertThat(properties.getRelatedCryptographicAssets())
                            .hasSize(2)
                            .extracting(RelatedCryptographicAsset::getType)
                            .containsOnly("algorithm");
                    final List<String> refs =
                            properties.getRelatedCryptographicAssets().stream()
                                    .map(RelatedCryptographicAsset::getRef)
                                    .toList();
                    assertThat(properties.getCryptoRefArray())
                            .containsExactlyInAnyOrderElementsOf(refs);
                    assertThat(refs)
                            .containsExactlyInAnyOrderElementsOf(
                                    bom.getComponents().stream()
                                            .filter(c -> !"IPSec".equals(c.getName()))
                                            .map(Component::getBomRef)
                                            .toList());
                });
    }

    @Test
    void savedFileIsValidCycloneDx17(@TempDir Path directory) throws IOException {
        final CBOMOutputFile outputFile = new CBOMOutputFile();
        outputFile.add(List.of(new RSA(detectionLocation)));
        final File file = directory.resolve("cbom.json").toFile();
        outputFile.saveTo(file);
        final String json = Files.readString(file.toPath(), StandardCharsets.UTF_8);
        assertThat(json).contains("\"specVersion\" : \"1.7\"");
        assertThat(new JsonParser().validate(json, Version.VERSION_17)).isEmpty();
    }

    @Test
    void everyAlgorithmFamilyIsInTheRegistry() throws IOException {
        final List<String> registry = registryEnum("algorithmFamiliesEnum");
        for (AlgorithmFamily family : AlgorithmFamily.values()) {
            assertThat(CycloneDxRegistry.algorithmFamily(family))
                    .as(family.name())
                    .isPresent()
                    .hasValueSatisfying(value -> assertThat(registry).contains(value));
        }
    }

    @Test
    void everyModelCurveIsInTheRegistry() throws IOException {
        final List<String> registry = registryEnum("ellipticCurvesEnum");
        final List<com.ibm.mapper.model.EllipticCurve> curves =
                Stream.of(
                                new com.ibm.mapper.model.curves.Brainpoolp256r1(detectionLocation),
                                new com.ibm.mapper.model.curves.Brainpoolp384r1(detectionLocation),
                                new com.ibm.mapper.model.curves.Brainpoolp512r1(detectionLocation),
                                new com.ibm.mapper.model.curves.Curve25519(detectionLocation),
                                new com.ibm.mapper.model.curves.Curve448(detectionLocation),
                                new com.ibm.mapper.model.curves.Edwards25519(detectionLocation),
                                new com.ibm.mapper.model.curves.Edwards448(detectionLocation),
                                new com.ibm.mapper.model.curves.Secp192r1(detectionLocation),
                                new com.ibm.mapper.model.curves.Secp224r1(detectionLocation),
                                new com.ibm.mapper.model.curves.Secp256k1(detectionLocation),
                                new com.ibm.mapper.model.curves.Secp256r1(detectionLocation),
                                new com.ibm.mapper.model.curves.Secp384r1(detectionLocation),
                                new com.ibm.mapper.model.curves.Secp521r1(detectionLocation),
                                new com.ibm.mapper.model.curves.Sect163k1(detectionLocation),
                                new com.ibm.mapper.model.curves.Sect163r2(detectionLocation),
                                new com.ibm.mapper.model.curves.Sect233k1(detectionLocation),
                                new com.ibm.mapper.model.curves.Sect233r1(detectionLocation),
                                new com.ibm.mapper.model.curves.Sect283k1(detectionLocation),
                                new com.ibm.mapper.model.curves.Sect283r1(detectionLocation),
                                new com.ibm.mapper.model.curves.Sect409k1(detectionLocation),
                                new com.ibm.mapper.model.curves.Sect409r1(detectionLocation),
                                new com.ibm.mapper.model.curves.Sect571k1(detectionLocation),
                                new com.ibm.mapper.model.curves.Sect571r1(detectionLocation))
                        .map(com.ibm.mapper.model.EllipticCurve.class::cast)
                        .toList();
        final List<String> emitted = new ArrayList<>();
        for (com.ibm.mapper.model.EllipticCurve curve : curves) {
            assertThat(CycloneDxRegistry.ellipticCurve(curve)).as(curve.asString()).isPresent();
            emitted.add(CycloneDxRegistry.ellipticCurve(curve).orElseThrow());
        }
        assertThat(registry).containsAll(emitted);
    }

    private static List<String> registryEnum(String name) throws IOException {
        try (var in =
                CycloneDx17Test.class
                        .getClassLoader()
                        .getResourceAsStream("cryptography-defs.schema.json")) {
            assertThat(in).isNotNull();
            final JsonNode node =
                    new ObjectMapper().readTree(in).path("definitions").path(name).path("enum");
            final List<String> values = new ArrayList<>();
            node.forEach(v -> values.add(v.asText()));
            return values;
        }
    }
}
