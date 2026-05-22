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
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.Mode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.pyca.PycaCipherMapper;
import com.ibm.mapper.mapper.pyca.PycaDigestMapper;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.algorithms.ANSIX963;
import com.ibm.mapper.model.algorithms.CMAC;
import com.ibm.mapper.model.algorithms.ConcatenationKDF;
import com.ibm.mapper.model.algorithms.HKDF;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.Scrypt;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.model.mode.CTR;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

public class PycaKeyDerivationContextTranslator implements IContextTranslation<Tree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<Tree> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof Algorithm<Tree> algorithm) {
            // hash algorithm
            Optional<String> possibleKind = detectionContext.get("kind");
            if (possibleKind.isPresent()) {
                final String kind = possibleKind.get();
                return switch (kind) {
                    case "hkdf" -> {
                        final PycaDigestMapper digestMapper = new PycaDigestMapper();
                        yield digestMapper
                                .parse(algorithm.asString(), detectionLocation)
                                .map(HKDF::new)
                                .map(
                                        kdf -> {
                                            kdf.put(new KeyDerivation(detectionLocation));
                                            return kdf;
                                        });
                    }
                    case "hmac" -> {
                        final PycaDigestMapper digestMapper = new PycaDigestMapper();
                        yield digestMapper
                                .parse(algorithm.asString(), detectionLocation)
                                .map(HMAC::new)
                                .map(
                                        kdf -> {
                                            kdf.put(new KeyDerivation(detectionLocation));
                                            return kdf;
                                        });
                    }
                    case "cmac" -> {
                        final PycaCipherMapper cipherMapper = new PycaCipherMapper();
                        yield cipherMapper
                                .parse(algorithm.asString(), detectionLocation)
                                .map(
                                        c -> {
                                            if (c instanceof Cipher cipher) {
                                                return new CMAC(cipher);
                                            }
                                            return null;
                                        })
                                .map(
                                        kdf -> {
                                            kdf.put(new KeyDerivation(detectionLocation));
                                            return kdf;
                                        });
                    }
                    case "pbkdf2" -> {
                        final PycaDigestMapper digestMapper = new PycaDigestMapper();
                        yield digestMapper
                                .parse(algorithm.asString(), detectionLocation)
                                .map(
                                        kdf -> {
                                            final PBKDF2 pbkdf2 = new PBKDF2(kdf);
                                            pbkdf2.put(new KeyDerivation(detectionLocation));
                                            return pbkdf2;
                                        });
                    }
                    case "concatkdf" -> {
                        final PycaDigestMapper digestMapper = new PycaDigestMapper();
                        yield digestMapper
                                .parse(algorithm.asString(), detectionLocation)
                                .map(
                                        digest -> {
                                            final ConcatenationKDF concatenationKDF =
                                                    new ConcatenationKDF(digest);
                                            concatenationKDF.put(
                                                    new KeyDerivation(detectionLocation));
                                            return concatenationKDF;
                                        });
                    }
                    case "x963" -> {
                        final PycaDigestMapper digestMapper = new PycaDigestMapper();
                        yield digestMapper
                                .parse(algorithm.asString(), detectionLocation)
                                .map(
                                        kdf -> {
                                            final ANSIX963 ansix963 = new ANSIX963(kdf);
                                            ansix963.put(new KeyDerivation(detectionLocation));
                                            return ansix963;
                                        });
                    }
                    default -> Optional.empty();
                };
            }
        } else if (value instanceof Mode<Tree> mode) {
            if (mode.asString().equalsIgnoreCase("CounterMode")) {
                return Optional.of(new CTR(detectionLocation));
            }
            return Optional.empty();
        } else if (value instanceof KeySize<Tree> keySize) {
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        } else if (value instanceof ValueAction<Tree> action) {
            return Optional.of(action.asString().toUpperCase().trim())
                    .map(
                            str ->
                                    switch (action.asString().toUpperCase().trim()) {
                                        case "SCRYPT" -> new Scrypt(detectionLocation);
                                        default -> null;
                                    })
                    .map(
                            kdf -> {
                                kdf.put(new KeyDerivation(detectionLocation));
                                return kdf;
                            });
        }
        return Optional.empty();
    }
}
