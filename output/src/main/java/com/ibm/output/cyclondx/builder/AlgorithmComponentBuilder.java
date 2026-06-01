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

import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.ExtendableOutputFunction;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.Provider;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
    @Nullable private INode provider;

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
            @Nullable INode curve,
            @Nullable INode provider) {
        this.component = component;
        this.cryptoProperties = cryptoProperties;
        this.algorithmProperties = algorithmProperties;
        this.algorithm = algorithm;
        this.parameterSetIdentifier = parameterSetIdentifier;
        this.mode = mode;
        this.padding = padding;
        this.curve = curve;
        this.provider = provider;
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
                curve,
                provider);
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
                curve,
                provider);
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
                    curve,
                    provider);
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
                curve,
                provider);
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
                    curve,
                    provider);
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
                curve,
                provider);
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
                    curve,
                    provider);
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
                curve,
                provider);
    }

    @Override
    public @Nonnull IAlgorithmComponentBuilder curve(@Nullable INode curve) {
        this.curve = curve;
        if (curve instanceof EllipticCurve ellipticCurve) {
            this.algorithmProperties.setCurve(ellipticCurve.asString());
        }
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve,
                provider);
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
                    curve,
                    provider);
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
                curve,
                provider);
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
                    curve,
                    provider);
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
                curve,
                provider);
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
                curve,
                provider);
    }

    @Override
    public @Nonnull IAlgorithmComponentBuilder provider(@Nullable INode provider) {
        if (provider instanceof Provider p) {
            List<org.cyclonedx.model.Property> props = new ArrayList<>();
            org.cyclonedx.model.Property prop = new org.cyclonedx.model.Property();
            prop.setName("jca-provider");
            prop.setValue(p.getName());
            props.add(prop);
            this.component.setProperties(props);
        }
        return new AlgorithmComponentBuilder(
                component,
                cryptoProperties,
                algorithmProperties,
                algorithm,
                parameterSetIdentifier,
                mode,
                padding,
                curve,
                provider);
    }

    @Override
    public @Nonnull Component build() {

        if (parameterSetIdentifier != null) {
            this.algorithmProperties.setParameterSetIdentifier(parameterSetIdentifier.asString());
        }
        this.cryptoProperties.setAssetType(AssetType.ALGORITHM);
        this.cryptoProperties.setAlgorithmProperties(this.algorithmProperties);

        this.component.setCryptoProperties(this.cryptoProperties);
        this.component.setType(Component.Type.CRYPTOGRAPHIC_ASSET);
        this.component.setBomRef(UUID.randomUUID().toString());
        this.component.setName(
                Optional.ofNullable(algorithm).map(INode::asString).orElse("Unknown"));

        return this.component;
    }
}
