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
package com.ibm.output.cyclondx.builder;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.ExtendableOutputFunction;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.KeyWrap;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.StreamCipher;
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
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.CCM;
import com.ibm.mapper.model.mode.CFB;
import com.ibm.mapper.model.mode.CTR;
import com.ibm.mapper.model.mode.ECB;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.mode.OFB;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.model.padding.PKCS5;
import com.ibm.mapper.model.padding.PKCS7;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.crypto.enums.Mode;
import org.cyclonedx.model.component.crypto.enums.Padding;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.cyclonedx.model.component.evidence.Occurrence;

public class AlgorithmComponentBuilder implements IAlgorithmComponentBuilder {
    @Nonnull private final Component component;
    @Nonnull private final CryptoProperties cryptoProperties;
    @Nonnull private final AlgorithmProperties algorithmProperties;

    @Nullable private INode algorithm;
    @Nullable private INode parameterSetIdentifier;
    @Nullable private INode mode;
    @Nullable private INode padding;
    @Nullable private INode curve;

    private static final Map<String, String> CURVE_TO_NAMESPACED = new HashMap<>();
    private static final Map<String, String> ALGORITHM_TO_FAMILY = new HashMap<>();

    static {
        CURVE_TO_NAMESPACED.put("secp256r1", "nist/P-256");
        CURVE_TO_NAMESPACED.put("secp384r1", "nist/P-384");
        CURVE_TO_NAMESPACED.put("secp521r1", "nist/P-521");
        CURVE_TO_NAMESPACED.put("secp256k1", "secg/secp256k1");
        CURVE_TO_NAMESPACED.put("secp224r1", "nist/P-224");
        CURVE_TO_NAMESPACED.put("secp192r1", "nist/P-192");
        CURVE_TO_NAMESPACED.put("sect163k1", "secg/sect163k1");
        CURVE_TO_NAMESPACED.put("sect163r2", "secg/sect163r2");
        CURVE_TO_NAMESPACED.put("sect233k1", "secg/sect233k1");
        CURVE_TO_NAMESPACED.put("sect233r1", "secg/sect233r1");
        CURVE_TO_NAMESPACED.put("sect283k1", "secg/sect283k1");
        CURVE_TO_NAMESPACED.put("sect283r1", "secg/sect283r1");
        CURVE_TO_NAMESPACED.put("sect409k1", "secg/sect409k1");
        CURVE_TO_NAMESPACED.put("sect409r1", "secg/sect409r1");
        CURVE_TO_NAMESPACED.put("sect571k1", "secg/sect571k1");
        CURVE_TO_NAMESPACED.put("sect571r1", "secg/sect571r1");
        CURVE_TO_NAMESPACED.put("Brainpoolp256r1", "brainpool/brainpoolP256r1");
        CURVE_TO_NAMESPACED.put("Brainpoolp384r1", "brainpool/brainpoolP384r1");
        CURVE_TO_NAMESPACED.put("Brainpoolp512r1", "brainpool/brainpoolP512r1");
        CURVE_TO_NAMESPACED.put("Edwards25519", "other/Ed25519");
        CURVE_TO_NAMESPACED.put("Edwards448", "other/Ed448");
        CURVE_TO_NAMESPACED.put("Curve25519", "other/Curve25519");
        CURVE_TO_NAMESPACED.put("Curve448", "other/Curve448");

        ALGORITHM_TO_FAMILY.put("3DES", "3DES");
        ALGORITHM_TO_FAMILY.put("AES", "AES");
        ALGORITHM_TO_FAMILY.put("ARIA", "ARIA");
        ALGORITHM_TO_FAMILY.put("Argon2", "Argon2");
        ALGORITHM_TO_FAMILY.put("Blowfish", "Blowfish");
        ALGORITHM_TO_FAMILY.put("CAST5", "CAST5");
        ALGORITHM_TO_FAMILY.put("CAST6", "CAST6");
        ALGORITHM_TO_FAMILY.put("CAMELLIA", "CAMELLIA");
        ALGORITHM_TO_FAMILY.put("ChaCha20", "ChaCha20");
        ALGORITHM_TO_FAMILY.put("DES", "DES");
        ALGORITHM_TO_FAMILY.put("DSA", "DSA");
        ALGORITHM_TO_FAMILY.put("ECDH", "ECDH");
        ALGORITHM_TO_FAMILY.put("ECDSA", "ECDSA");
        ALGORITHM_TO_FAMILY.put("ECIES", "ECIES");
        ALGORITHM_TO_FAMILY.put("EdDSA", "EdDSA");
        ALGORITHM_TO_FAMILY.put("HKDF", "HKDF");
        ALGORITHM_TO_FAMILY.put("HMAC", "HMAC");
        ALGORITHM_TO_FAMILY.put("ML-KEM", "ML-KEM");
        ALGORITHM_TO_FAMILY.put("ML-DSA", "ML-DSA");
        ALGORITHM_TO_FAMILY.put("PBKDF2", "PBKDF2");
        ALGORITHM_TO_FAMILY.put("Poly1305", "Poly1305");
        ALGORITHM_TO_FAMILY.put("RC2", "RC2");
        ALGORITHM_TO_FAMILY.put("RC4", "RC4");
        ALGORITHM_TO_FAMILY.put("RSA", "RSAES-PKCS1");
        ALGORITHM_TO_FAMILY.put("RSA-PSS", "RSASSA-PSS");
        ALGORITHM_TO_FAMILY.put("scrypt", "scrypt");
        ALGORITHM_TO_FAMILY.put("SEED", "SEED");
        ALGORITHM_TO_FAMILY.put("SLH-DSA", "SLH-DSA");
        ALGORITHM_TO_FAMILY.put("Salsa20", "Salsa20");
        ALGORITHM_TO_FAMILY.put("SHA-1", "SHA-1");
        ALGORITHM_TO_FAMILY.put("SHA-224", "SHA-2");
        ALGORITHM_TO_FAMILY.put("SHA-256", "SHA-2");
        ALGORITHM_TO_FAMILY.put("SHA-384", "SHA-2");
        ALGORITHM_TO_FAMILY.put("SHA-512", "SHA-2");
        ALGORITHM_TO_FAMILY.put("SHA-512/224", "SHA-2");
        ALGORITHM_TO_FAMILY.put("SHA-512/256", "SHA-2");
        ALGORITHM_TO_FAMILY.put("SHA3", "SHA-3");
        ALGORITHM_TO_FAMILY.put("SHA3-256", "SHA-3");
        ALGORITHM_TO_FAMILY.put("SHA3-384", "SHA-3");
        ALGORITHM_TO_FAMILY.put("SHA3-512", "SHA-3");
        ALGORITHM_TO_FAMILY.put("secp192r1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("secp224r1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("secp256r1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("secp256k1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("secp384r1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("secp521r1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("Brainpoolp256r1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("Brainpoolp384r1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("Brainpoolp512r1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("Edwards25519", "EdDSA");
        ALGORITHM_TO_FAMILY.put("Edwards448", "EdDSA");
        ALGORITHM_TO_FAMILY.put("Curve25519", "ECDH");
        ALGORITHM_TO_FAMILY.put("Curve448", "ECDH");
        ALGORITHM_TO_FAMILY.put("sect163k1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("sect163r2", "ECDSA");
        ALGORITHM_TO_FAMILY.put("sect233k1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("sect233r1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("sect283k1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("sect283r1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("sect409k1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("sect409r1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("sect571k1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("sect571r1", "ECDSA");
        ALGORITHM_TO_FAMILY.put("X25519", "ECDH");
        ALGORITHM_TO_FAMILY.put("X448", "ECDH");
        ALGORITHM_TO_FAMILY.put("Ed25519", "EdDSA");
        ALGORITHM_TO_FAMILY.put("Ed448", "EdDSA");
    }

    protected AlgorithmComponentBuilder() {
        this.component = new Component();
        this.cryptoProperties = new CryptoProperties();
        this.algorithmProperties = new AlgorithmProperties();
    }

    @SuppressWarnings("java:S107")
    public AlgorithmComponentBuilder(
            @Nonnull Component component,
            @Nonnull CryptoProperties cryptoProperties,
            @Nonnull AlgorithmProperties algorithmProperties,
            @Nullable INode algorithm,
            @Nullable INode parameterSetIdentifier,
            @Nullable INode mode,
            @Nullable INode padding,
            @Nullable INode curve) {
        this.component = component;
        this.cryptoProperties = cryptoProperties;
        this.algorithmProperties = algorithmProperties;
        this.algorithm = algorithm;
        this.parameterSetIdentifier = parameterSetIdentifier;
        this.mode = mode;
        this.padding = padding;
        this.curve = curve;
    }

    @Nonnull
    public static IAlgorithmComponentBuilder create() {
        return new AlgorithmComponentBuilder();
    }

    @Override
    public @Nonnull IAlgorithmComponentBuilder algorithm(@Nullable INode algorithm) {
        this.algorithm = algorithm;
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @Nonnull IAlgorithmComponentBuilder parameterSetIdentifier(
            @Nullable INode parameterSetIdentifier) {
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @Nonnull IAlgorithmComponentBuilder mode(@Nullable INode mode) {
        if (mode == null) {
            return new AlgorithmComponentBuilder(
                    component,
                    cryptoProperties,
                    algorithmProperties,
                    algorithm,
                    parameterSetIdentifier,
                    this.mode,
                    padding,
                    curve);
        }
        this.mode = mode;
        Mode cxMode;
        if (mode instanceof CBC) {
            cxMode = Mode.CBC;
        } else if (mode instanceof CCM) {
            cxMode = Mode.CCM;
        } else if (mode instanceof CFB) {
            cxMode = Mode.CFB;
        } else if (mode instanceof CTR) {
            cxMode = Mode.CTR;
        } else if (mode instanceof ECB) {
            cxMode = Mode.ECB;
        } else if (mode instanceof GCM) {
            cxMode = Mode.GCM;
        } else if (mode instanceof OFB) {
            cxMode = Mode.OFB;
        } else {
            cxMode = Mode.OTHER;
        }
        this.algorithmProperties.setMode(cxMode);
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @Nonnull IAlgorithmComponentBuilder primitive(@Nullable INode primitive) {
        if (primitive == null) {
            return new AlgorithmComponentBuilder(
                    component,
                    cryptoProperties,
                    algorithmProperties,
                    algorithm,
                    parameterSetIdentifier,
                    mode,
                    padding,
                    curve);
        }
        Primitive primitives;
        if (primitive.is(AuthenticatedEncryption.class)) {
            primitives = Primitive.AE;
        } else if (primitive.is(BlockCipher.class)) {
            primitives = Primitive.BLOCK_CIPHER;
        } else if (primitive.is(Mac.class)) {
            primitives = Primitive.MAC;
        } else if (primitive.is(MessageDigest.class)) {
            primitives = Primitive.HASH;
        } else if (primitive.is(KeyDerivationFunction.class)
                || primitive.is(PasswordBasedKeyDerivationFunction.class)
                || primitive.is(PasswordBasedEncryption.class)) {
            primitives = Primitive.KDF;
        } else if (primitive.is(PseudorandomNumberGenerator.class)) {
            primitives = Primitive.DRBG;
        } else if (primitive.is(Signature.class)
                || primitive.is(ProbabilisticSignatureScheme.class)) {
            primitives = Primitive.SIGNATURE;
        } else if (primitive.is(StreamCipher.class)) {
            primitives = Primitive.STREAM_CIPHER;
        } else if (primitive.is(PublicKeyEncryption.class)) {
            primitives = Primitive.PKE;
        } else if (primitive.is(KeyAgreement.class)) {
            primitives = Primitive.KEY_AGREE;
        } else if (primitive.is(KeyEncapsulationMechanism.class)) {
            primitives = Primitive.KEM;
        } else if (primitive.is(KeyWrap.class)) {
            // TODO: cyclonedx-core-java 13.2.0 does not expose Primitive.KEY_WRAP; needs dependency
            // upgrade
            primitives = Primitive.OTHER;
        } else if (primitive.is(ExtendableOutputFunction.class)) {
            primitives = Primitive.XOF;
        } else {
            primitives = Primitive.OTHER;
        }
        this.algorithmProperties.setPrimitive(primitives);
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @Nonnull IAlgorithmComponentBuilder padding(@Nullable INode padding) {
        if (padding == null) {
            return new AlgorithmComponentBuilder(
                    component,
                    cryptoProperties,
                    algorithmProperties,
                    algorithm,
                    parameterSetIdentifier,
                    mode,
                    this.padding,
                    curve);
        }

        this.padding = padding;
        Padding cxPadding;
        if (padding instanceof OAEP) {
            cxPadding = Padding.OAEP;
        } else if (padding instanceof PKCS5) {
            cxPadding = Padding.PKCS5;
        } else if (padding instanceof PKCS7) {
            cxPadding = Padding.PKCS7;
        } else if (padding instanceof PKCS1) {
            cxPadding = Padding.PKCS1V15;
        } else {
            cxPadding = Padding.OTHER;
        }
        this.algorithmProperties.setPadding(cxPadding);
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @Nonnull IAlgorithmComponentBuilder curve(@Nullable INode curve) {
        this.curve = curve;
        if (curve instanceof EllipticCurve ellipticCurve) {
            String namespaced =
                    CURVE_TO_NAMESPACED.getOrDefault(
                            ellipticCurve.asString(), ellipticCurve.asString());
            this.algorithmProperties.setEllipticCurve(namespaced);
        }
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @Nonnull IAlgorithmComponentBuilder algorithmFamily(@Nullable String family) {
        if (family != null) {
            this.algorithmProperties.setAlgorithmFamily(family);
        }
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @Nonnull IAlgorithmComponentBuilder cryptoFunctions(@Nullable INode... cryptoFunctions) {
        if (cryptoFunctions == null || cryptoFunctions.length == 0) {
            return new AlgorithmComponentBuilder(
                    component,
                    cryptoProperties,
                    algorithmProperties,
                    algorithm,
                    parameterSetIdentifier,
                    mode,
                    padding,
                    curve);
        }

        List<CryptoFunction> functions =
                Arrays.stream(cryptoFunctions)
                        .filter(Objects::nonNull)
                        .filter(Functionality.class::isInstance)
                        .map(
                                node -> {
                                    if (node.is(Tag.class)) {
                                        return CryptoFunction.TAG;
                                    } else if (node.is(Sign.class)) {
                                        return CryptoFunction.SIGN;
                                    } else if (node.is(Digest.class)) {
                                        return CryptoFunction.DIGEST;
                                    } else if (node.is(Verify.class)) {
                                        return CryptoFunction.VERIFY;
                                    } else if (node.is(Decrypt.class)) {
                                        return CryptoFunction.DECRYPT;
                                    } else if (node.is(Encrypt.class)) {
                                        return CryptoFunction.ENCRYPT;
                                    } else if (node.is(Generate.class)) {
                                        return CryptoFunction.GENERATE;
                                    } else if (node.is(Decapsulate.class)) {
                                        return CryptoFunction.DECAPSULATE;
                                    } else if (node.is(Encapsulate.class)) {
                                        return CryptoFunction.ENCAPSULATE;
                                    } else if (node.is(KeyDerivation.class)) {
                                        return CryptoFunction.KEYDERIVE;
                                    } else if (node.is(KeyGeneration.class)) {
                                        return CryptoFunction.KEYGEN;
                                    } else {
                                        return CryptoFunction.OTHER;
                                    }
                                })
                        .toList();

        this.algorithmProperties.setCryptoFunctions(functions);
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @Nonnull IAlgorithmComponentBuilder occurrences(@Nullable Occurrence... occurrences) {
        if (occurrences == null) {
            return new AlgorithmComponentBuilder(
                    component,
                    cryptoProperties,
                    algorithmProperties,
                    algorithm,
                    parameterSetIdentifier,
                    mode,
                    padding,
                    curve);
        }

        final Evidence evidence = new Evidence();
        evidence.setOccurrences(List.of(occurrences));
        this.component.setEvidence(evidence);

        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @Nonnull IAlgorithmComponentBuilder oid(@Nullable INode oid) {
        if (oid instanceof Oid oid1) {
            this.cryptoProperties.setOid(oid1.getValue());
        }
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve);
    }

    @Override
    public @Nonnull Component build() {

        if (parameterSetIdentifier != null) {
            this.algorithmProperties.setParameterSetIdentifier(parameterSetIdentifier.asString());
        }
        this.cryptoProperties.setAssetType(AssetType.ALGORITHM);
        this.cryptoProperties.setAlgorithmProperties(this.algorithmProperties);

        if (algorithm != null) {
            String name = ((Algorithm) algorithm).getName();
            String family = ALGORITHM_TO_FAMILY.get(name);
            if (family == null && name.startsWith("EC-")) {
                family = ALGORITHM_TO_FAMILY.get(name.substring(3));
            }
            if (family != null) {
                this.algorithmProperties.setAlgorithmFamily(family);
            }
        }

        this.component.setCryptoProperties(this.cryptoProperties);
        this.component.setType(Component.Type.CRYPTOGRAPHIC_ASSET);
        this.component.setBomRef(UUID.randomUUID().toString());
        this.component.setName(
                Optional.ofNullable(algorithm).map(INode::asString).orElse("Unknown"));

        return this.component;
    }
}
