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
package com.ibm.mapper.model.algorithms;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.ascon.Ascon128;
import com.ibm.mapper.model.algorithms.ascon.AsconHash;
import com.ibm.mapper.model.algorithms.ascon.AsconXof;
import com.ibm.mapper.model.algorithms.blake.BLAKE2b;
import com.ibm.mapper.model.algorithms.blake.BLAKE2s;
import com.ibm.mapper.model.algorithms.cast.CAST128;
import com.ibm.mapper.model.algorithms.cast.CAST256;
import com.ibm.mapper.model.algorithms.shake.SHAKE;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * Conformance guardrail: verifies that each schema-named algorithm's composed {@code asString()}
 * output is a valid instance of its CycloneDX pattern, rather than just equal to a hand-picked
 * literal (see {@link AlgorithmNameCompositionTest} for the exact-string assertions).
 *
 * <p>The {@code cyclonedx} pattern strings are copied verbatim from the CycloneDX cryptography
 * registry (https://cyclonedx.org/registry/cryptography/#pattern-format and cryptography-defs.json)
 * and translated to a regex by {@link #toRegex(String)}: {@code [x]} → optional, {@code (a|b)} →
 * alternatives, {@code {placeholder}} → a value regex, everything else is a literal.
 */
class AlgorithmSchemaConformanceTest {

    static final DetectionLocation TEST =
            new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "TEST");

    /** Matches the hash/digest names this project emits (SHA-256, SHA3-512, MD5, RIPEMD-160, …). */
    private static final String HASH =
            "(?:SHA-\\d+(?:/\\d+)?|SHA3-\\d+|SHAKE\\d+|MD\\d|RIPEMD-\\d+|Whirlpool|SM3|BLAKE\\w+)";

    /**
     * Regexes substituted for {@code {placeholder}} tokens; unknown placeholders use {@link #ANY}.
     */
    private static final String ANY = "[A-Za-z0-9.\\-/]+";

    private static final Map<String, String> PLACEHOLDERS =
            Map.ofEntries(
                    Map.entry("keyLength", "\\d+"),
                    Map.entry("length", "\\d+"),
                    Map.entry("tagLength", "\\d+"),
                    Map.entry("saltLength", "\\d+"),
                    Map.entry("ivLength", "\\d+"),
                    Map.entry("ivlen", "\\d+"),
                    Map.entry("dkLen", "\\d+"),
                    Map.entry("dkmLength", "\\d+"),
                    Map.entry("iterations", "\\d+"),
                    Map.entry("outputLength", "\\d+"),
                    Map.entry("N", "\\d+"),
                    Map.entry("r", "\\d+"),
                    Map.entry("p", "\\d+"),
                    Map.entry("hashAlgorithm", HASH),
                    Map.entry("digestAlgorithm", HASH),
                    Map.entry("prfFunction", "[A-Za-z0-9\\-]+"),
                    Map.entry("maskGenAlgorithm", "[A-Za-z0-9]+"),
                    Map.entry("ellipticCurve", "[A-Za-z0-9]+"),
                    Map.entry("cipherAlgorithm", "[A-Za-z0-9\\-]+"),
                    Map.entry("encryptionAlgorithm", "[A-Za-z0-9\\-]+"),
                    Map.entry("mode", "[A-Za-z0-9]+"),
                    Map.entry("padding", "[A-Za-z0-9]+"),
                    Map.entry("kdf", "[A-Za-z0-9\\-]+"),
                    Map.entry("mac", "[A-Za-z0-9\\-]+"),
                    Map.entry("namedGroup", "[A-Za-z0-9.\\-]+"));

    /** Translates a CycloneDX pattern-format string into an anchored-free Java regex body. */
    static String toRegex(String pattern) {
        final StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < pattern.length()) {
            final char c = pattern.charAt(i);
            switch (c) {
                case '[' -> sb.append("(?:"); // start optional group
                case ']' -> sb.append(")?"); // end optional group
                case '(' -> sb.append("(?:"); // start alternatives group
                case ')' -> sb.append(")"); // end alternatives group
                case '|' -> sb.append('|');
                case '{' -> {
                    final int end = pattern.indexOf('}', i);
                    final String name = pattern.substring(i + 1, end);
                    sb.append(PLACEHOLDERS.getOrDefault(name, ANY));
                    i = end; // advance to '}'
                }
                default -> {
                    if ("\\.*+?^$/-".indexOf(c) >= 0) {
                        sb.append('\\');
                    }
                    sb.append(c);
                }
            }
            i++;
        }
        return sb.toString();
    }

    static void assertConforms(String cyclonedxPattern, INode algorithm) {
        final Pattern regex = Pattern.compile("^" + toRegex(cyclonedxPattern) + "$");
        final String name = algorithm.asString();
        assertThat(regex.matcher(name).matches())
                .withFailMessage(
                        "'%s' does not conform to CycloneDX pattern '%s' (regex %s)",
                        name, cyclonedxPattern, regex.pattern())
                .isTrue();
    }

    @Test
    void translatorHandlesOptionalAlternativeAndPlaceholder() {
        // (128|192|256) is a required alternation once present; {padding} is a free trailing token
        final Pattern aes = Pattern.compile("^" + toRegex("AES-(128|192|256)[-{padding}]") + "$");
        assertThat(aes.matcher("AES-256").matches()).isTrue();
        assertThat(aes.matcher("AES-256-PKCS7").matches()).isTrue();
        assertThat(aes.matcher("AES-999").matches()).isFalse(); // 999 is not an allowed key length
        assertThat(aes.matcher("AES").matches()).isFalse(); // key length is required here
        assertThat(aes.matcher("SHA-256-AES").matches()).isFalse(); // wrong prefix
        // literal dot must not act as a wildcard
        final Pattern rsa = Pattern.compile("^" + toRegex("RSA-PKCS1-1.5") + "$");
        assertThat(rsa.matcher("RSA-PKCS1-1.5").matches()).isTrue();
        assertThat(rsa.matcher("RSA-PKCS1-1X5").matches()).isFalse();
    }

    @Test
    void blockCiphersConform() {
        Mode cbc = new CBC(TEST);
        assertConforms(
                "AES[-(128|192|256)][-(ECB|CBC|CFB|OFB|CTR|XTS|CTS)][-{padding}]",
                new AES(256, cbc, TEST));
        assertConforms("DES[-{keyLength}][-{mode}]", new DES(56, cbc, TEST));
        assertConforms("3DES[-{keyLength}][-{mode}]", new TripleDES(168, cbc, TEST));
        assertConforms("ARIA-(128|192|256)[-{mode}][-{padding}]", new Aria(256, cbc, TEST));
        assertConforms("CAMELLIA-(128|192|256)[-{mode}][-{padding}]", new Camellia(256, cbc, TEST));
        assertConforms("Twofish-(128|192|256)[-{mode}][-{padding}]", new Twofish(256, cbc, TEST));
        assertConforms("Serpent-(128|192|256)[-{mode}][-{padding}]", new Serpent(256, cbc, TEST));
        assertConforms("Blowfish[-{keyLength}][-{mode}][-{padding}]", new Blowfish(128, cbc, TEST));
        assertConforms("CAST5[-{keyLength}][-{mode}]", new CAST128(128, cbc, TEST));
        assertConforms("CAST6[-{keyLength}][-{mode}]", new CAST256(256, cbc, TEST));
        assertConforms("RC2[-{keyLength}][-{mode}]", new RC2(64, cbc, TEST));
        assertConforms("RC5[-{keyLength}][-{mode}]", new RC5(128, cbc, TEST));
        assertConforms("RC6[-{keyLength}][-{mode}]", new RC6(128, cbc, TEST));
        assertConforms("IDEA[-{mode}]", new IDEA(cbc, TEST));
        assertConforms("SM4[-(ECB|CBC|CFB|OFB|CTR|XTS)][-{padding}]", new SM4(cbc, TEST));
        assertConforms("SEED-128[-{mode}][-{padding}]", new SEED(cbc, TEST));
    }

    @Test
    void streamAndAeadCiphersConform() {
        assertConforms("RC4[-{keyLength}]", new RC4(128, TEST));
        assertConforms("ChaCha20-Poly1305", new ChaCha20Poly1305(TEST));
        assertConforms("Ascon-AEAD128", new Ascon128(TEST));
    }

    @Test
    void hashesAndXofsConform() {
        assertConforms("SHA-(224|256|384|512|512/224|512/256)", new SHA2(256, TEST));
        assertConforms("SHA3-(224|256|384|512)", new SHA3(256, TEST));
        assertConforms("SHAKE(128|256)", new SHAKE(256, TEST));
        assertConforms("Ascon-Hash256", new AsconHash(TEST));
        assertConforms("Ascon-XOF128", new AsconXof(TEST));
        assertConforms("BLAKE2b-(160|256|384|512)", new BLAKE2b(256, false, TEST));
        assertConforms("BLAKE2s-(160|256)", new BLAKE2s(256, false, TEST));
    }

    @Test
    void macsConform() {
        assertConforms("HMAC[-{hashAlgorithm}][-{tagLength}]", new HMAC(new SHA2(256, TEST)));
        assertConforms("CMAC[-{cipherAlgorithm}][-{length}]", new CMAC(new AES(TEST)));
    }

    @Test
    void signaturesAndKeyExchangeConform() {
        RSA rsaSig = new RSA(Signature.class, TEST);
        rsaSig.put(new SHA2(256, TEST));
        assertConforms("RSA-PKCS1-1.5[-{digestAlgorithm}][-{keyLength}]", rsaSig);
        assertConforms(
                "RSA-PSS[-{hashAlgorithm}][-{maskGenAlgorithm}][-{saltLength}][-{keyLength}]",
                new RSAssaPSS(TEST));

        DSA dsa = new DSA(TEST);
        dsa.put(new KeyLength(2048, TEST));
        dsa.put(new SHA2(256, TEST));
        assertConforms("DSA[-{length}][-{hashAlgorithm}]", dsa);

        ECDSA ecdsa = new ECDSA(new EllipticCurve("secp256r1", TEST), TEST);
        ecdsa.put(new SHA2(256, TEST));
        assertConforms("ECDSA[-{ellipticCurve}][-{hashAlgorithm}]", ecdsa);

        assertConforms("ML-DSA-(44|65|87)", new MLDSA(65, TEST));
        assertConforms("ML-KEM-(512|768|1024)", new MLKEM(768, TEST));
        assertConforms("FFMQV[-{namedGroup}]", new MQV(TEST));
    }

    @Test
    void derivationFunctionsConform() {
        assertConforms("HKDF[-{hashAlgorithm}]", new HKDF(new SHA2(256, TEST)));
        assertConforms("scrypt[-{N}][-{r}][-{p}][-{dkLen}]", new Scrypt(TEST));
        assertConforms(
                "SP800_108_(CounterKDF|FeedbackKDF|DoublePipelineKDF|KMAC)[-{prfFunction}][-{dkmLength}]",
                new KDFCounter(TEST));
        assertConforms("ANSI-KDF-X9.63[-{hashAlgorithm}]", new ANSIX963(TEST));
    }
}
