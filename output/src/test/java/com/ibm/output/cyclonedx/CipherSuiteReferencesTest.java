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
package com.ibm.output.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.mapper.ssl.CipherSuiteMapper;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.output.cyclondx.CBOMOutputFile;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.junit.jupiter.api.Test;

/**
 * A protocol component that is merged into an existing one of the same name must not leave the
 * dependencies its builder registered under its own (discarded) bom-ref, nor lose its cipher
 * suites; and a suite under a TLS must not make TLS depend on itself. Both happened for source
 * scans as well: two suites in one Java file, or a suite nested under TLS by {@code
 * CipherSuiteReorganizer}.
 */
class CipherSuiteReferencesTest {

    private final IBundle bundle = () -> "Test";
    private final DetectionLocation location =
            new DetectionLocation("src/Main.java", 3, 7, List.of(), bundle);

    @Nonnull
    private CipherSuite suite(@Nonnull String name, @Nonnull INode... algorithms) {
        final CipherSuite suite = new CipherSuite(name, location);
        suite.put(new AssetCollection(List.of(algorithms)));
        return suite;
    }

    @Test
    void twoSuitesBecomeOneTlsWithBothNamesAndNoDanglingRef() {
        final CBOMOutputFile output = new CBOMOutputFile();
        output.add(
                List.of(
                        suite(
                                "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
                                new DH(KeyAgreement.class, location),
                                new AES(128, new CBC(location), location))));
        output.add(List.of(suite("TLS_RSA_WITH_AES_128_CBC_SHA", new RSA(location))));
        final Bom bom = output.getBom();
        assertThat(problems(bom)).isEmpty();
        final Component tls = component(bom, "TLS");
        assertThat(tls.getCryptoProperties().getProtocolProperties().getCipherSuites())
                .extracting(org.cyclonedx.model.component.crypto.CipherSuite::getName)
                .containsExactly(
                        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA");
        // the second suite's algorithm is a dependency of the kept TLS component
        assertThat(dependsOnNames(bom, tls)).contains("RSA", "AES-128-CBC");
    }

    @Test
    void aSuiteUnderTlsDoesNotMakeTlsDependOnItself() {
        final TLS tls = new TLS(location);
        tls.put(suite("TLS_RSA_WITH_AES_128_CBC_SHA", new RSA(location)));
        final CBOMOutputFile output = new CBOMOutputFile();
        output.add(List.of(tls));
        final Bom bom = output.getBom();
        assertThat(problems(bom)).isEmpty();
        final Component component = component(bom, "TLS");
        // absence: no TLS -> TLS, and the suite name is no longer lost
        assertThat(dependsOnNames(bom, component)).doesNotContain("TLS").contains("RSA");
        assertThat(component.getCryptoProperties().getProtocolProperties().getCipherSuites())
                .extracting(org.cyclonedx.model.component.crypto.CipherSuite::getName)
                .containsExactly("TLS_RSA_WITH_AES_128_CBC_SHA");
        assertThat(component.getCryptoProperties().getProtocolProperties().getCryptoRefArray())
                .doesNotContain(component.getBomRef());
    }

    /**
     * {@code TLS_RSA_WITH_...} names RSA for both key exchange and authentication, and the mapper
     * keeps the suite's MAC/PRF hash under the authentication algorithm. The suite lists each
     * algorithm once and the hash with them.
     */
    @Test
    void suiteListsEachAlgorithmOnceAndItsHash() {
        final CBOMOutputFile output = new CBOMOutputFile();
        output.add(List.of(mapped("TLS_RSA_WITH_AES_128_CBC_SHA")));
        output.add(List.of(mapped("TLS_RSA_WITH_AES_256_GCM_SHA384")));
        final Bom bom = output.getBom();
        assertThat(problems(bom)).isEmpty();
        final Map<String, List<String>> suites = suiteAlgorithmNames(bom);
        assertThat(suites.get("TLS_RSA_WITH_AES_128_CBC_SHA"))
                .containsExactly("RSA", "AES-128-CBC", "SHA-1");
        assertThat(suites.get("TLS_RSA_WITH_AES_256_GCM_SHA384"))
                .containsExactly("RSA", "AES-256-GCM", "SHA-384");
        // absence: no suite lists a ref twice
        component(bom, "TLS")
                .getCryptoProperties()
                .getProtocolProperties()
                .getCipherSuites()
                .forEach(suite -> assertThat(suite.getAlgorithms()).doesNotHaveDuplicates());
    }

    /**
     * A TLS 1.3 suite has its hash as an asset of its own already; it is not listed twice, and no
     * hash is taken from the AEAD cipher.
     */
    @Test
    void tls13SuiteListsItsHashOnce() {
        final CBOMOutputFile output = new CBOMOutputFile();
        output.add(List.of(mapped("TLS_AES_256_GCM_SHA384")));
        output.add(List.of(mapped("TLS_CHACHA20_POLY1305_SHA256")));
        final Bom bom = output.getBom();
        assertThat(problems(bom)).isEmpty();
        assertThat(suiteAlgorithmNames(bom).get("TLS_AES_256_GCM_SHA384"))
                .containsExactly("AES-256-GCM", "SHA-384");
        // absence: the AEAD's own Poly1305 is part of the cipher, not a suite algorithm
        assertThat(suiteAlgorithmNames(bom).get("TLS_CHACHA20_POLY1305_SHA256"))
                .containsExactly("ChaCha20-Poly1305", "SHA-256");
    }

    @Nonnull
    private INode mapped(@Nonnull String suiteName) {
        return new CipherSuiteMapper().parse(suiteName, location).orElseThrow();
    }

    @Nonnull
    private static Map<String, List<String>> suiteAlgorithmNames(@Nonnull Bom bom) {
        final Map<String, String> names = new HashMap<>();
        bom.getComponents().forEach(c -> names.put(c.getBomRef(), c.getName()));
        final Map<String, List<String>> result = new HashMap<>();
        component(bom, "TLS")
                .getCryptoProperties()
                .getProtocolProperties()
                .getCipherSuites()
                .forEach(
                        suite ->
                                result.put(
                                        suite.getName(),
                                        suite.getAlgorithms().stream().map(names::get).toList()));
        return result;
    }

    @Nonnull
    private static Component component(@Nonnull Bom bom, @Nonnull String name) {
        return bom.getComponents().stream()
                .filter(c -> c.getName().equals(name))
                .findFirst()
                .orElseThrow();
    }

    @Nonnull
    private static List<String> dependsOnNames(@Nonnull Bom bom, @Nonnull Component component) {
        final Map<String, String> names = new HashMap<>();
        bom.getComponents().forEach(c -> names.put(c.getBomRef(), c.getName()));
        final List<String> result = new ArrayList<>();
        bom.getDependencies().stream()
                .filter(d -> d.getRef().equals(component.getBomRef()))
                .forEach(
                        d -> d.getDependencies().forEach(on -> result.add(names.get(on.getRef()))));
        return result;
    }

    @Nonnull
    private static List<String> problems(@Nonnull Bom bom) {
        final Set<String> refs = new HashSet<>();
        bom.getComponents().forEach(c -> refs.add(c.getBomRef()));
        final List<String> problems = new ArrayList<>();
        for (Dependency dependency : bom.getDependencies()) {
            if (!refs.contains(dependency.getRef())) {
                problems.add("dangling ref " + dependency.getRef());
            }
            if (dependency.getDependencies() != null) {
                for (Dependency on : dependency.getDependencies()) {
                    if (!refs.contains(on.getRef())) {
                        problems.add("dangling dependsOn " + on.getRef());
                    }
                    if (on.getRef().equals(dependency.getRef())) {
                        problems.add("self-dependency " + on.getRef());
                    }
                }
            }
        }
        return problems;
    }
}
