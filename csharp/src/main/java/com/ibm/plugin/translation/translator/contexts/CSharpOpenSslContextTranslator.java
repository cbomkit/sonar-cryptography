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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.CipherSuite;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.IterationCount;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.ParameterIdentifier;
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.ssl.CipherSuiteMapper;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.NumberOfIterations;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.ANSIX942;
import com.ibm.mapper.model.algorithms.ANSIX963;
import com.ibm.mapper.model.algorithms.Aria;
import com.ibm.mapper.model.algorithms.Blowfish;
import com.ibm.mapper.model.algorithms.CMAC;
import com.ibm.mapper.model.algorithms.Camellia;
import com.ibm.mapper.model.algorithms.ChaCha20;
import com.ibm.mapper.model.algorithms.ChaCha20Poly1305;
import com.ibm.mapper.model.algorithms.ConcatenationKDF;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.Ed448;
import com.ibm.mapper.model.algorithms.HKDF;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.IDEA;
import com.ibm.mapper.model.algorithms.KDFCounter;
import com.ibm.mapper.model.algorithms.KMAC;
import com.ibm.mapper.model.algorithms.Kerberos;
import com.ibm.mapper.model.algorithms.MD2;
import com.ibm.mapper.model.algorithms.MD4;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.MLDSA;
import com.ibm.mapper.model.algorithms.MLKEM;
import com.ibm.mapper.model.algorithms.PBKDF1;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.PKCS12PBE;
import com.ibm.mapper.model.algorithms.Poly1305;
import com.ibm.mapper.model.algorithms.RC2;
import com.ibm.mapper.model.algorithms.RC4;
import com.ibm.mapper.model.algorithms.RC5;
import com.ibm.mapper.model.algorithms.RIPEMD;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.algorithms.SEED;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.mapper.model.algorithms.SM3;
import com.ibm.mapper.model.algorithms.SM4;
import com.ibm.mapper.model.algorithms.Scrypt;
import com.ibm.mapper.model.algorithms.SipHash;
import com.ibm.mapper.model.algorithms.Whirlpool;
import com.ibm.mapper.model.algorithms.X25519;
import com.ibm.mapper.model.algorithms.X448;
import com.ibm.mapper.model.algorithms.blake.BLAKE2b;
import com.ibm.mapper.model.algorithms.blake.BLAKE2s;
import com.ibm.mapper.model.algorithms.cast.CAST128;
import com.ibm.mapper.model.algorithms.shake.SHAKE;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.CCM;
import com.ibm.mapper.model.mode.CFB;
import com.ibm.mapper.model.mode.CTR;
import com.ibm.mapper.model.mode.ECB;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.mode.KW;
import com.ibm.mapper.model.mode.KWP;
import com.ibm.mapper.model.mode.OCB;
import com.ibm.mapper.model.mode.OFB;
import com.ibm.mapper.model.mode.XTS;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.rules.detection.openssl.OpenSslApi;
import com.ibm.plugin.rules.detection.openssl.OpenSslDetectionRules;
import com.ibm.plugin.rules.detection.openssl.OpenSslDigest;
import com.ibm.plugin.rules.detection.openssl.OpenSslKey;
import com.ibm.plugin.rules.detection.openssl.OpenSslRandom;
import com.ibm.plugin.rules.detection.openssl.OpenSslTls;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Turns the OpenSSL detections into mapper nodes.
 *
 * <p>One translator for all of OpenSSL, reached from {@code CSharpTranslator} by the {@code
 * openssl} context property rather than by the context class, because the rule sets span five
 * contexts and share one vocabulary (see {@code OpenSslDetectionRules}).
 *
 * <h2>Every value goes through a closed set</h2>
 *
 * <p>All OpenSSL rules match on an {@code ANY} receiver, since a {@code static extern} call has no
 * type to match on, so the guard that keeps them honest is not in the rule but here: a name that is
 * not in {@link OpenSslApi}'s tables, or a cipher-suite token that {@code
 * CipherSuiteMapper.findCipherSuite} does not know, yields {@code Optional.empty()} and the
 * detection contributes nothing. That is the same mechanism {@code
 * CSharpProtocolContextTranslator#dotNetProtocol} uses for the .NET protocol enums, and it is what
 * makes it safe to read a value out of a call that could belong to anybody.
 *
 * <p>Two shapes are refused on purpose rather than by accident, and they are worth naming because
 * they look like losses:
 *
 * <ul>
 *   <li>A key size, iteration count or version that arrives in a variable or a method parameter.
 *       The engine resolves an identifier only through a constant or a single-assignment local (see
 *       {@code CSharpDetectionEngine}'s guards G1 and G4) and never falls back to the identifier's
 *       spelling, so such a call is reported without that child -- not with a guess.
 *   <li>A constant this plugin does not recognise. {@code SSL_CTX_set_min_proto_version(ctx,
 *       SomeWrapper.TLS1_4_VERSION)} resolves to the name {@code TLS1_4_VERSION}, which is in no
 *       table, so nothing is reported for that line at all.
 * </ul>
 *
 * <h2>Where the function name comes from</h2>
 *
 * <p>What distinguishes the members of the three big families -- the {@code EVP_<cipher>()}
 * functions, the {@code EVP_<md>()} functions and the {@code SSL_METHOD} functions -- is the
 * function name itself. Each has one rule per function, generated in a loop from the same table
 * this translator reads, and each rule carries its own name as its action constant. So the name
 * arrives here as an ordinary detected value and is looked up in that table, exactly as every other
 * rule set in this project states what it found.
 *
 * <p>It was first written as three rules over the whole name list, with the name read back out of
 * {@code DetectionLocation#keywords()}. That worked, but it was a coupling nothing else in the
 * project relies on, and the keyword is filled for a different purpose (the CBOM writer uses it as
 * a finding's additional context). One rule per function costs 189 more rules in a scan's
 * per-statement loop -- 255 to 441 for C# -- and buys an architecture a reader can follow from the
 * rule to the node without knowing what a keyword is.
 */
@SuppressWarnings({"java:S1200", "java:S6539"})
public final class CSharpOpenSslContextTranslator implements IContextTranslation<CSharpTree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<CSharpTree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        final String kind = detectionContext.get(OpenSslDetectionRules.CONTEXT_KEY).orElse("");

        if (value instanceof ValueAction<?> action) {
            return translateAction(action.asString(), detectionLocation);
        }
        if (value instanceof Algorithm<?> algorithm) {
            return translateAlgorithmName(kind, algorithm.asString(), detectionLocation);
        }
        if (value instanceof ParameterIdentifier<?> parameter) {
            return translateParameter(kind, parameter.asString(), detectionLocation);
        }
        if (value instanceof CipherSuite<?> cipherSuite) {
            return cipherSuites(cipherSuite.asString(), detectionLocation);
        }
        if (value instanceof IterationCount<?> iterationCount) {
            return Optional.of(
                    new NumberOfIterations(iterationCount.getValue(), detectionLocation));
        }
        if (value instanceof SaltSize<?> saltSize) {
            return Optional.of(new SaltLength(saltSize.getValue(), detectionLocation));
        }
        if (value instanceof KeySize<?> keySize) {
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        }
        return Optional.empty();
    }

    // =====================================================================
    // Actions
    // =====================================================================

    /**
     * The node a rule's action constant stands for.
     *
     * <p>The three families -- the {@code EVP_CIPHER} functions, the {@code EVP_MD} functions and
     * the {@code SSL_METHOD} functions -- have one rule each per function, and each rule carries
     * its own function name as the action constant. So the name arrives here as the value, the way
     * every other rule set in this project delivers one, and is looked up in the same table the
     * rules took their names from. Nothing is read back out of the detection location.
     */
    @Nonnull
    private Optional<INode> translateAction(
            @Nonnull String action, @Nonnull DetectionLocation detectionLocation) {
        final Optional<INode> fromFunctionName = functionName(action, detectionLocation);
        if (fromFunctionName.isPresent()) {
            return fromFunctionName;
        }
        return switch (action) {
            case OpenSslTls.TLS -> Optional.of(new TLS(detectionLocation));
            case OpenSslDigest.HMAC -> Optional.of(new HMAC(detectionLocation));
            case OpenSslKey.RSA -> Optional.of(new RSA(detectionLocation));
            case OpenSslKey.DSA -> Optional.of(new DSA(detectionLocation));
            case OpenSslKey.DH -> Optional.of(new DH(detectionLocation));
            case OpenSslKey.RSA_ENCRYPT ->
                    Optional.of(rsaWith(new Encrypt(detectionLocation), detectionLocation));
            case OpenSslKey.RSA_DECRYPT ->
                    Optional.of(rsaWith(new Decrypt(detectionLocation), detectionLocation));
            case OpenSslKey.RSA_SIGN ->
                    Optional.of(rsaWith(new Sign(detectionLocation), detectionLocation));
            case OpenSslKey.RSA_VERIFY ->
                    Optional.of(rsaWith(new Verify(detectionLocation), detectionLocation));
            case OpenSslKey.PBKDF2 -> Optional.of(new PBKDF2(detectionLocation));
            // PKCS5_PBKDF2_HMAC_SHA1 names its pseudo-random function in the function name, so
            // this one call site yields the complete PBKDF2-SHA-1 identity.
            case OpenSslKey.PBKDF2_SHA1 -> Optional.of(new PBKDF2(new SHA(detectionLocation)));
            case OpenSslKey.SCRYPT -> Optional.of(new Scrypt(detectionLocation));
            case OpenSslRandom.DRBG ->
                    Optional.of(
                            new com.ibm.mapper.model.Algorithm(
                                    OpenSslRandom.DRBG,
                                    PseudorandomNumberGenerator.class,
                                    detectionLocation));
            default -> Optional.empty();
        };
    }

    @Nonnull
    private static INode rsaWith(
            @Nonnull INode functionality, @Nonnull DetectionLocation detectionLocation) {
        final RSA rsa = new RSA(detectionLocation);
        rsa.put(functionality);
        return rsa;
    }

    /**
     * The node an OpenSSL function name stands for, when the action constant is one.
     *
     * <p>The three tables are disjoint -- a name is a cipher, a digest or an {@code SSL_METHOD},
     * never two of them -- so trying each in turn cannot be ambiguous. An action that is not a
     * function name at all (the fixed constants below) falls through to the switch.
     */
    @Nonnull
    private Optional<INode> functionName(
            @Nonnull String action, @Nonnull DetectionLocation detectionLocation) {
        final Optional<INode> cipher =
                OpenSslApi.cipherFunction(action).flatMap(s -> symmetric(s, detectionLocation));
        if (cipher.isPresent()) {
            return cipher;
        }
        final Optional<INode> md =
                OpenSslApi.digestFunction(action).flatMap(s -> digest(s, detectionLocation));
        if (md.isPresent()) {
            return md;
        }
        return OpenSslApi.sslMethod(action).flatMap(s -> protocol(s, detectionLocation));
    }

    // =====================================================================
    // Symmetric ciphers
    // =====================================================================

    /**
     * The node an {@code EVP_CIPHER} specification stands for: the algorithm, with its key length
     * and mode attached when the function name states them.
     */
    @Nonnull
    private static Optional<INode> symmetric(
            @Nonnull OpenSslApi.SymmetricSpec spec, @Nonnull DetectionLocation detectionLocation) {
        final com.ibm.mapper.model.Algorithm algorithm =
                switch (spec.algorithm()) {
                    case OpenSslApi.AES -> new AES(detectionLocation);
                    case OpenSslApi.ARIA -> new Aria(detectionLocation);
                    case OpenSslApi.CAMELLIA -> new Camellia(detectionLocation);
                    case OpenSslApi.CHACHA20 -> new ChaCha20(detectionLocation);
                    case OpenSslApi.CHACHA20_POLY1305 -> new ChaCha20Poly1305(detectionLocation);
                    case OpenSslApi.DES -> new DES(detectionLocation);
                    // Two-key and three-key Triple DES are the same mapper node; the key length
                    // below is what tells them apart, which is also how CycloneDX spells it.
                    case OpenSslApi.DES_EDE, OpenSslApi.DES_EDE3 -> new DESede(detectionLocation);
                    case OpenSslApi.RC2 -> new RC2(detectionLocation);
                    case OpenSslApi.RC4 -> new RC4(detectionLocation);
                    case OpenSslApi.RC5 -> new RC5(detectionLocation);
                    case OpenSslApi.BLOWFISH -> new Blowfish(detectionLocation);
                    case OpenSslApi.CAST5 -> new CAST128(detectionLocation);
                    case OpenSslApi.IDEA -> new IDEA(detectionLocation);
                    case OpenSslApi.SEED -> new SEED(detectionLocation);
                    case OpenSslApi.SM4 -> new SM4(detectionLocation);
                    default -> null;
                };
        if (algorithm == null) {
            // Unreachable while the table and this switch agree, and an empty result rather than
            // an exception or a generic node if a family is ever added to only one of the two:
            // nothing is better than a cipher reported under the wrong name.
            return Optional.empty();
        }
        if (spec.keyBits() != OpenSslApi.KEY_LENGTH_UNSPECIFIED) {
            algorithm.put(new KeyLength(spec.keyBits(), detectionLocation));
        }
        mode(spec.mode(), detectionLocation).ifPresent(algorithm::put);
        return Optional.of(algorithm);
    }

    /**
     * The mode node a function name's suffix stands for.
     *
     * <p>{@code cfb1}, {@code cfb8}, {@code cfb64} and {@code cfb128} are all CFB and differ only
     * in how many bits are fed back, which the {@code CFB(int, ...)} constructor records as the
     * mode's block size. {@code wrap} and {@code wrap_pad} are AES key wrap with and without
     * padding.
     */
    @Nonnull
    private static Optional<Mode> mode(
            @Nullable String mode, @Nonnull DetectionLocation detectionLocation) {
        if (mode == null) {
            return Optional.empty();
        }
        return switch (mode) {
            case "CBC" -> Optional.of(new CBC(detectionLocation));
            case "ECB" -> Optional.of(new ECB(detectionLocation));
            case "OFB" -> Optional.of(new OFB(detectionLocation));
            case "CTR" -> Optional.of(new CTR(detectionLocation));
            case "GCM" -> Optional.of(new GCM(detectionLocation));
            case "CCM" -> Optional.of(new CCM(detectionLocation));
            case "OCB" -> Optional.of(new OCB(detectionLocation));
            case "XTS" -> Optional.of(new XTS(detectionLocation));
            case "KW" -> Optional.of(new KW(detectionLocation));
            case "KWP" -> Optional.of(new KWP(detectionLocation));
            case "CFB1" -> Optional.of(new CFB(1, detectionLocation));
            case "CFB8" -> Optional.of(new CFB(8, detectionLocation));
            case "CFB64" -> Optional.of(new CFB(64, detectionLocation));
            case "CFB128" -> Optional.of(new CFB(128, detectionLocation));
            default -> Optional.empty();
        };
    }

    // =====================================================================
    // Digests
    // =====================================================================

    @Nonnull
    private static Optional<INode> digest(
            @Nonnull OpenSslApi.DigestSpec spec, @Nonnull DetectionLocation detectionLocation) {
        final MessageDigest messageDigest =
                switch (spec.algorithm()) {
                    case OpenSslApi.SHA1 -> new SHA(detectionLocation);
                    case OpenSslApi.SHA2 -> new SHA2(spec.digestSize(), detectionLocation);
                    case OpenSslApi.SHA3 -> new SHA3(spec.digestSize(), detectionLocation);
                    case OpenSslApi.SHAKE -> new SHAKE(spec.digestSize(), detectionLocation);
                    case OpenSslApi.MD2 -> new MD2(detectionLocation);
                    case OpenSslApi.MD4 -> new MD4(detectionLocation);
                    case OpenSslApi.MD5 -> new MD5(detectionLocation);
                    case OpenSslApi.RIPEMD -> new RIPEMD(spec.digestSize(), detectionLocation);
                    case OpenSslApi.BLAKE2B -> new BLAKE2b(detectionLocation);
                    case OpenSslApi.BLAKE2S -> new BLAKE2s(detectionLocation);
                    case OpenSslApi.SM3 -> new SM3(detectionLocation);
                    case OpenSslApi.WHIRLPOOL -> new Whirlpool(detectionLocation);
                    // No default digest: see the comment in symmetric(). A family present in the
                    // table but missing here reports nothing rather than the wrong hash.
                    default -> null;
                };
        return Optional.ofNullable(messageDigest);
    }

    // =====================================================================
    // Protocols
    // =====================================================================

    /**
     * The protocol an {@code SSL_METHOD} function or a version constant stands for.
     *
     * <p>A TLS version becomes a versioned {@code TLS} node. SSL and DTLS get a plain {@code
     * Protocol} node under their own name, following the way {@code
     * CSharpProtocolContextTranslator} already reports {@code SslProtocols.Ssl3}: SSL is not TLS,
     * and the mapper has no DTLS model, so calling either one a {@code TLS} would misreport it.
     */
    @Nonnull
    private static Optional<INode> protocol(
            @Nonnull OpenSslApi.MethodSpec spec, @Nonnull DetectionLocation detectionLocation) {
        if (OpenSslApi.TLS.equals(spec.protocol())) {
            return spec.version() == null
                    ? Optional.of(new TLS(detectionLocation))
                    : Optional.of(new TLS(new Version(spec.version(), detectionLocation)));
        }
        final String name =
                spec.version() == null ? spec.protocol() : spec.protocol() + "v" + spec.version();
        return Optional.of(new Protocol(name, detectionLocation));
    }

    /**
     * The suites a cipher-selection string names.
     *
     * <p>Split on {@code :}, every token checked against the shared suite table, and only the ones
     * that are real suites kept -- the table already carries OpenSSL's own spellings, so {@code
     * ECDHE-RSA-AES256-GCM-SHA384} resolves through it. The result is a {@code TLS} node carrying a
     * {@code CipherSuiteCollection}, which is the shape the CBOM writer expects for a protocol's
     * suites. A string with no recognisable suite in it -- a list expression such as {@code
     * "HIGH:!aNULL"}, or an alias such as {@code "DEFAULT"} -- yields nothing.
     */
    @Nonnull
    private static Optional<INode> cipherSuites(
            @Nonnull String selection, @Nonnull DetectionLocation detectionLocation) {
        final List<com.ibm.mapper.model.CipherSuite> suites = new ArrayList<>();
        for (String token : selection.split(":")) {
            final String name = token.trim();
            if (name.isEmpty() || CipherSuiteMapper.findCipherSuite(name).isEmpty()) {
                continue;
            }
            new CipherSuiteMapper()
                    .parse(name, detectionLocation)
                    .filter(com.ibm.mapper.model.CipherSuite.class::isInstance)
                    .map(com.ibm.mapper.model.CipherSuite.class::cast)
                    .ifPresent(suites::add);
        }
        if (suites.isEmpty()) {
            return Optional.empty();
        }
        final TLS tls = new TLS(detectionLocation);
        tls.put(new CipherSuiteCollection(suites));
        return Optional.of(tls);
    }

    // =====================================================================
    // Algorithm-name strings
    // =====================================================================

    /** A name passed to one of the {@code *_fetch} / {@code *byname} / {@code Q_keygen} calls. */
    @Nonnull
    private Optional<INode> translateAlgorithmName(
            @Nonnull String kind,
            @Nonnull String name,
            @Nonnull DetectionLocation detectionLocation) {
        return switch (kind) {
            case "CIPHER" ->
                    OpenSslApi.cipherAlgorithmName(name)
                            .flatMap(spec -> symmetric(spec, detectionLocation));
            case "DIGEST" ->
                    OpenSslApi.digestAlgorithmName(name)
                            .flatMap(spec -> digest(spec, detectionLocation));
            case "KDF_FETCH" -> OpenSslApi.kdfName(name).flatMap(k -> kdf(k, detectionLocation));
            case "MAC_FETCH" -> OpenSslApi.macName(name).flatMap(m -> mac(m, detectionLocation));
            case "PKEY_Q_KEYGEN" -> keyType(name, detectionLocation);
            default -> Optional.empty();
        };
    }

    /**
     * The MAC an {@code EVP_MAC_fetch} name stands for.
     *
     * <p>No digest or cipher is attached. A MAC fetched by name carries neither: {@code
     * EVP_MAC_CTX_set_params} supplies the {@code "digest"} or {@code "cipher"} parameter later, in
     * a separate call whose own argument is already reported by the digest and cipher rules. An
     * HMAC node with a guessed SHA-256 beneath it would be an invention.
     */
    @Nonnull
    private static Optional<INode> mac(
            @Nonnull String macName, @Nonnull DetectionLocation detectionLocation) {
        return switch (macName) {
            case "HMAC" -> Optional.of(new HMAC(detectionLocation));
            case "CMAC" -> Optional.of(new CMAC(detectionLocation));
            case "KMAC-128" -> Optional.of(new KMAC(128, detectionLocation));
            case "KMAC-256" -> Optional.of(new KMAC(256, detectionLocation));
            case "Poly1305" -> Optional.of(new Poly1305(detectionLocation));
            case "SipHash" -> Optional.of(new SipHash(detectionLocation));
            default -> Optional.empty();
        };
    }

    /** The KDF an {@code EVP_KDF_fetch} name stands for. */
    @Nonnull
    private static Optional<INode> kdf(
            @Nonnull String kdfName, @Nonnull DetectionLocation detectionLocation) {
        return switch (kdfName) {
            case "PBKDF2" -> Optional.of(new PBKDF2(detectionLocation));
            case "PBKDF1" -> Optional.of(new PBKDF1(detectionLocation));
            case "SCRYPT" -> Optional.of(new Scrypt(detectionLocation));
            case "HKDF" -> Optional.of(new HKDF(detectionLocation));
            case "SSKDF" -> Optional.of(new ConcatenationKDF(detectionLocation));
            case "X942KDF" -> Optional.of(new ANSIX942(detectionLocation));
            case "X963KDF" -> Optional.of(new ANSIX963(detectionLocation));
            case "KBKDF" -> Optional.of(new KDFCounter(detectionLocation));
            case "KRB5KDF" -> Optional.of(new Kerberos(detectionLocation));
            case "PKCS12KDF" -> Optional.of(new PKCS12PBE(detectionLocation));
            default -> Optional.empty();
        };
    }

    /**
     * The algorithm an {@code EVP_PKEY_Q_keygen} type string stands for.
     *
     * <p>Only the types the man page lists are accepted. {@code "EC"} yields a curveless {@code EC}
     * node, and the curve arrives separately as that node's child from the variadic argument.
     */
    @Nonnull
    private static Optional<INode> keyType(
            @Nonnull String type, @Nonnull DetectionLocation detectionLocation) {
        return switch (type.trim().toUpperCase(java.util.Locale.ROOT)) {
            case "RSA" -> Optional.of(new RSA(detectionLocation));
            case "RSA-PSS" -> Optional.of(new RSAssaPSS(detectionLocation));
            case "EC" -> Optional.of(new EllipticCurveAlgorithm(detectionLocation));
            case "ED25519" -> Optional.of(new Ed25519(detectionLocation));
            case "ED448" -> Optional.of(new Ed448(detectionLocation));
            case "X25519" -> Optional.of(new X25519(detectionLocation));
            case "X448" -> Optional.of(new X448(detectionLocation));
            case "SM2" -> Optional.of(new SM2(detectionLocation));
            case "DSA" -> Optional.of(new DSA(detectionLocation));
            case "DH" -> Optional.of(new DH(detectionLocation));
            case "ML-DSA-44" -> Optional.of(new MLDSA(44, detectionLocation));
            case "ML-DSA-65" -> Optional.of(new MLDSA(65, detectionLocation));
            case "ML-DSA-87" -> Optional.of(new MLDSA(87, detectionLocation));
            case "ML-KEM-512" -> Optional.of(new MLKEM(512, detectionLocation));
            case "ML-KEM-768" -> Optional.of(new MLKEM(768, detectionLocation));
            case "ML-KEM-1024" -> Optional.of(new MLKEM(1024, detectionLocation));
            default -> Optional.empty();
        };
    }

    // =====================================================================
    // Constants carried as a name or as a number
    // =====================================================================

    /**
     * A constant that the engine resolved either to its member name or to its numeric value.
     *
     * <p>Which closed set to look it up in is decided by the rule's own context property, never by
     * the shape of the value: {@code 4} is OAEP padding under a padding rule and NID 4 under none
     * of them, and the two must not be able to swap.
     */
    @Nonnull
    private Optional<INode> translateParameter(
            @Nonnull String kind,
            @Nonnull String rawNameOrValue,
            @Nonnull DetectionLocation detectionLocation) {
        final String nameOrValue = normalizeConstant(rawNameOrValue);
        return switch (kind) {
            case "TLS" ->
                    OpenSslApi.protocolVersion(nameOrValue)
                            .flatMap(spec -> protocol(spec, detectionLocation));
            case "PADDING" ->
                    OpenSslApi.rsaPadding(nameOrValue).flatMap(p -> padding(p, detectionLocation));
            case "EC_CURVE_NID" ->
                    OpenSslApi.curveNid(nameOrValue)
                            .map(
                                    curve ->
                                            new EllipticCurveAlgorithm(
                                                    new EllipticCurve(curve, detectionLocation)));
            case "EC_CURVE_NAME" ->
                    OpenSslApi.curveName(nameOrValue)
                            .map(
                                    curve ->
                                            new EllipticCurveAlgorithm(
                                                    new EllipticCurve(curve, detectionLocation)));
            // The one variadic argument of EVP_PKEY_Q_keygen: a size_t for "RSA" and a curve-name
            // string for "EC", per EVP_PKEY_keygen(3). A number is therefore the key length and a
            // recognised curve name is the curve; anything else is neither and is dropped.
            case "PKEY_Q_KEYGEN" -> keygenParameter(nameOrValue, detectionLocation);
            default -> Optional.empty();
        };
    }

    /**
     * A resolved constant in the spelling the tables use: a member name unchanged, a number in
     * decimal.
     *
     * <p>Needed because a C# integer literal does not always reach a value factory as an {@code
     * Integer}. The frontend classifies a decimal literal as an integer and resolves it to one, but
     * a hexadecimal or binary literal arrives as the literal's own text, and OpenSSL's constants
     * are conventionally written in hex -- {@code const int TLS1_2_VERSION = 0x0303;} is how every
     * interop layer declares them, because that is how {@code prov_ssl.h} does. Normalising here
     * rather than listing {@code "0x0303"} beside {@code "771"} in the table keeps one spelling per
     * constant and covers {@code 0X}, {@code 0b}, digit separators and the {@code u}/{@code l}
     * suffixes at the same time.
     *
     * <p>Anything that is not a numeric literal is returned untouched, so a member name is
     * unaffected.
     */
    @Nonnull
    private static String normalizeConstant(@Nonnull String value) {
        String text = value.trim().replace("_", "");
        int end = text.length();
        while (end > 0 && "uUlL".indexOf(text.charAt(end - 1)) >= 0) {
            end--;
        }
        text = text.substring(0, end);
        final int radix;
        if (text.regionMatches(true, 0, "0x", 0, 2)) {
            radix = 16;
        } else if (text.regionMatches(true, 0, "0b", 0, 2)) {
            radix = 2;
        } else {
            return value.trim();
        }
        try {
            return Long.toString(Long.parseLong(text.substring(2), radix));
        } catch (NumberFormatException e) {
            return value.trim();
        }
    }

    @Nonnull
    private static Optional<INode> keygenParameter(
            @Nonnull String nameOrValue, @Nonnull DetectionLocation detectionLocation) {
        final String text = nameOrValue.trim();
        if (text.chars().allMatch(Character::isDigit) && !text.isEmpty()) {
            return Optional.of(new KeyLength(Integer.parseInt(text), detectionLocation));
        }
        return OpenSslApi.curveName(text).map(curve -> new EllipticCurve(curve, detectionLocation));
    }

    /**
     * The padding node an {@code RSA_*_PADDING} constant stands for.
     *
     * <p>{@code RSA_NO_PADDING} is recorded as a padding named {@code NONE}: it is a finding in its
     * own right -- raw RSA -- and leaving it out would make a textbook-RSA call site look like one
     * whose padding simply was not readable. {@code PSS} and {@code X9.31} have no padding node in
     * the mapper model, where PSS is an algorithm and X9.31 a signature scheme, so both are
     * recorded as a plain named padding, as {@code DotNetPaddingNames} already does for {@code
     * RSASignaturePadding.Pss}.
     */
    @Nonnull
    private static Optional<INode> padding(
            @Nonnull String padding, @Nonnull DetectionLocation detectionLocation) {
        return switch (padding) {
            case "PKCS1" -> Optional.of(new PKCS1(detectionLocation));
            case "OAEP" -> Optional.of(new OAEP(detectionLocation));
            case "NONE", "PSS", "X9.31" -> Optional.of(new Padding(padding, detectionLocation));
            default -> Optional.empty();
        };
    }
}
