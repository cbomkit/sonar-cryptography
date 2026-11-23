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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Identifier;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.IdentifierCollection;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.output.cyclondx.CBOMOutputFile;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.model.Bom;
import org.junit.jupiter.api.Test;

/**
 * Proves that a CBOM built from source-scan nodes (detection locations without properties) is
 * byte-for-byte what it was before detection properties existed. The golden file {@code
 * source-scan-cbom.golden.json} was recorded with the output module as it was before {@code
 * DetectionLocation#properties} was introduced; only the random parts (serial number, timestamp,
 * bom-refs) and the order of the dependency list (kept in a hash map keyed by random bom-refs) are
 * normalised.
 *
 * <p>Re-recorded deliberately once since: the cipher suite now also lists its MAC/PRF hash (SHA-256
 * of {@code ..._SHA256}, which the model keeps under the DSA), so the suite's {@code algorithms}
 * and the TLS component's {@code dependsOn} each gained that one ref. Nothing else changed.
 * Re-record with {@code -DrecordGolden=<path>}.
 */
class SourceScanOutputUnchangedTest {

    private static final String GOLDEN = "source-scan-cbom.golden.json";
    private static final Pattern UUID =
            Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

    private final IBundle bundle = () -> "Test";
    private final DetectionLocation plain =
            new DetectionLocation("src/Main.java", 3, 7, List.of(), bundle);
    private final DetectionLocation withKeyword =
            new DetectionLocation("src/Other.java", 12, 4, List.of("getInstance"), bundle);

    @Nonnull
    private List<INode> sourceScanNodes() {
        final CipherSuite cipherSuite =
                new CipherSuite("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", plain);
        final DH dh = new DH(KeyAgreement.class, plain);
        final AES aes = new AES(256, new CBC(plain), plain);
        final DSA dsa = new DSA(new SHA2(256, plain));
        dsa.put(new Oid("2.16.840.1.101.3.4.3.2", plain));
        cipherSuite.put(new AssetCollection(List.of(dh, aes, dsa)));
        cipherSuite.put(
                new IdentifierCollection(
                        List.of(new Identifier("0x00", plain), new Identifier("0x6A", plain))));

        final RSA rsa = new RSA(withKeyword);
        rsa.put(new KeyLength(2048, withKeyword));
        rsa.put(new Encrypt(withKeyword));
        final PublicKey publicKey = new PublicKey((PublicKeyEncryption) rsa);

        return List.of(
                new TLS(new Version("1.2", plain)),
                cipherSuite,
                publicKey,
                new RSA(plain),
                new SaltLength(128, withKeyword));
    }

    @Test
    void sourceScanCbomIsUnchanged() throws Exception {
        final CBOMOutputFile outputFile = new CBOMOutputFile();
        sourceScanNodes().forEach(node -> outputFile.add(List.of(node)));
        final String actual = normalise(outputFile.getBom());

        final String record = System.getProperty("recordGolden");
        if (record != null) {
            Files.writeString(Path.of(record), actual, StandardCharsets.UTF_8);
        }
        final String expected;
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(GOLDEN)) {
            assertThat(in).isNotNull();
            expected = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        assertThat(actual).isEqualTo(expected);
        assertThat(actual).doesNotContain("\"properties\"");
    }

    @Nonnull
    private static String normalise(@Nonnull Bom bom) throws Exception {
        final String json =
                BomGeneratorFactory.createJson(org.cyclonedx.Version.VERSION_16, bom)
                        .toJsonString();
        final ObjectMapper mapper = new ObjectMapper();
        // components live in a hash map keyed by name, and related crypto material names contain
        // a random bom-ref: order them by their content with every bom-ref blanked out
        final ObjectNode parsed = (ObjectNode) mapper.readTree(json);
        sortArray(parsed.get("components"), node -> UUID.matcher(node.toString()).replaceAll(""));
        final Map<String, String> ids = new LinkedHashMap<>();
        final Matcher matcher = UUID.matcher(mapper.writeValueAsString(parsed));
        final StringBuilder replaced = new StringBuilder();
        while (matcher.find()) {
            final String id = ids.computeIfAbsent(matcher.group(), k -> "uuid-" + (ids.size() + 1));
            matcher.appendReplacement(replaced, id);
        }
        matcher.appendTail(replaced);

        final ObjectNode root = (ObjectNode) mapper.readTree(replaced.toString());
        ((ObjectNode) root.get("metadata")).put("timestamp", "<timestamp>");
        // dependencies live in a hash map keyed by random bom-refs
        sortArray(root.get("dependencies"), JsonNode::toString);
        return mapper.enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(root) + "\n";
    }

    private static void sortArray(@Nonnull JsonNode node, @Nonnull Function<JsonNode, String> key) {
        if (node instanceof ArrayNode array) {
            final List<JsonNode> sorted = new ArrayList<>();
            array.forEach(sorted::add);
            sorted.sort(Comparator.comparing(key));
            array.removeAll();
            sorted.forEach(array::add);
        }
    }
}
