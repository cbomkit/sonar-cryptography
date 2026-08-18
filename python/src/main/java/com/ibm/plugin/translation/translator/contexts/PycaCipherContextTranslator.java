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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.Mode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.pyca.PycaCipherMapper;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.KeyWrap;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.CCM;
import com.ibm.mapper.model.mode.CFB;
import com.ibm.mapper.model.mode.CTR;
import com.ibm.mapper.model.mode.EAX;
import com.ibm.mapper.model.mode.ECB;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.mode.GCMSIV;
import com.ibm.mapper.model.mode.KW;
import com.ibm.mapper.model.mode.KWP;
import com.ibm.mapper.model.mode.OCB;
import com.ibm.mapper.model.mode.OFB;
import com.ibm.mapper.model.mode.SIV;
import com.ibm.mapper.model.mode.XTS;
import com.ibm.mapper.model.padding.ANSIX923;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.model.padding.PKCS7;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1301")
public final class PycaCipherContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        final PycaCipherMapper pycaCipherMapper = new PycaCipherMapper();
        if (value instanceof Algorithm<Tree>
                && detectionContext instanceof DetectionContext context) {
            if (context.get("kind").map(k -> k.equals("AEAD")).orElse(false)) {
                return switch (value.asString().toUpperCase().trim()) {
                    case "AESGCM" ->
                            Optional.of(new AES(new GCM(detectionLocation), detectionLocation));
                    case "AESGCMIV" ->
                            Optional.of(new AES(new GCMSIV(detectionLocation), detectionLocation));
                    case "AESOCB3" ->
                            Optional.of(new AES(new OCB(3, detectionLocation), detectionLocation));
                    case "AESSIV" ->
                            Optional.of(new AES(new SIV(detectionLocation), detectionLocation));
                    case "AESCCM" ->
                            Optional.of(new AES(new CCM(detectionLocation), detectionLocation));
                    default -> Optional.empty();
                };
            }
            return pycaCipherMapper.parse(value.asString(), detectionLocation).map(i -> i);
        } else if (value instanceof ValueAction<Tree>
                && detectionContext instanceof DetectionContext context) {
            if (context.get("kind").map(k -> k.equals("padding")).orElse(false)) { // padding case
                return switch (value.asString().toUpperCase().trim()) {
                    case "PKCS7" -> Optional.of(new PKCS7(detectionLocation));
                    case "ANSIX923" -> Optional.of(new ANSIX923(detectionLocation));
                    case "OAEP" -> Optional.of(new OAEP(detectionLocation));
                    default -> Optional.empty();
                };
            }

            // Handle ValueAction with algorithm name (e.g., "AES", "DES", "DES3")
            // Get the algorithm name from the ValueAction
            String algorithmName = value.asString();
            return switch (algorithmName.trim().toUpperCase()) {
                case "PKCS1_OAEP" -> {
                    RSA rsaOaep = new RSA(PublicKeyEncryption.class, detectionLocation);
                    rsaOaep.put(new OAEP(detectionLocation));
                    yield Optional.of((INode) rsaOaep);
                }
                case "PKCS1_V1_5" -> {
                    RSA rsaPkcs1 = new RSA(PublicKeyEncryption.class, detectionLocation);
                    rsaPkcs1.put(new PKCS1(detectionLocation));
                    yield Optional.of((INode) rsaPkcs1);
                }
                case "HPKE" -> Optional.of(new EllipticCurveAlgorithm(detectionLocation));
                default -> pycaCipherMapper.parse(algorithmName, detectionLocation).map(i -> i);
            };
        } else if (value instanceof Mode<Tree> mode) {
            return switch (mode.asString().toUpperCase().trim()) {
                case "CBC", "MODE_CBC" -> Optional.of(new CBC(detectionLocation));
                case "CTR", "MODE_CTR" -> Optional.of(new CTR(detectionLocation));
                case "OFB", "MODE_OFB" -> Optional.of(new OFB(detectionLocation));
                case "MODE_OCB" -> Optional.of(new OCB(detectionLocation));
                case "CFB", "MODE_CFB" -> Optional.of(new CFB(detectionLocation));
                case "CFB8" -> Optional.of(new CFB(8, detectionLocation));
                case "GCM", "MODE_GCM" -> Optional.of(new GCM(detectionLocation));
                case "XTS" -> Optional.of(new XTS(detectionLocation));
                case "ECB", "MODE_ECB" -> Optional.of(new ECB(detectionLocation));
                case "MODE_EAX" -> Optional.of(new EAX(detectionLocation));
                case "CCM", "MODE_CCM" -> Optional.of(new CCM(detectionLocation));
                case "MODE_SIV" -> Optional.of(new SIV(detectionLocation));
                case "MODE_KW" -> Optional.of(new KW(detectionLocation));
                case "MODE_KWP" -> Optional.of(new KWP(detectionLocation));
                default -> Optional.empty();
            };
        } else if (value instanceof CipherAction<Tree> cipherAction
                && detectionContext instanceof DetectionContext context) {
            return switch (cipherAction.getAction()) {
                case DECRYPT -> Optional.of(new Decrypt(detectionLocation));
                case ENCRYPT -> Optional.of(new Encrypt(detectionLocation));
                case WRAP ->
                        context.get("algorithm")
                                .map(
                                        str ->
                                                switch (str.toUpperCase().trim()) {
                                                    case "AES" ->
                                                            new AES(
                                                                    KeyWrap.class,
                                                                    new AES(
                                                                            128,
                                                                            detectionLocation));
                                                    default -> null;
                                                })
                                .map(
                                        algo -> {
                                            algo.put(new Encapsulate(detectionLocation));
                                            return algo;
                                        });
                default -> Optional.empty();
            };
        } else if (value instanceof com.ibm.engine.model.BlockSize<Tree> blockSize) {
            return Optional.of(new BlockSize(blockSize.getValue(), detectionLocation));
        } else if (value instanceof KeySize<Tree> keySize) {
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        }
        return Optional.empty();
    }
}
