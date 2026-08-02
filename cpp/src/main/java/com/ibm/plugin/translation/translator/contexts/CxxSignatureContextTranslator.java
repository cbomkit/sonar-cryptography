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
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.EdDSA;
import com.ibm.mapper.model.algorithms.MLDSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SLHDSA;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translator for C++ signature detection contexts.
 *
 * <p>This translator handles the translation of signature-related detection values to the mapper
 * model nodes. Supports RSA, DSA, ECDSA, EdDSA, post-quantum, and SM2 signatures.
 */
public final class CxxSignatureContextTranslator implements IContextTranslation<AstNode> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<AstNode> || value instanceof Algorithm<AstNode>) {
            String algorithmName = value.asString().toUpperCase().trim();

            // RSA-PSS Signatures (PKCS#1 v2.1 / RSASSA-PSS) — must check before generic RSA-
            if (algorithmName.startsWith("RSA-PSS-")) {
                RSAssaPSS rsapss = new RSAssaPSS(detectionLocation);
                if (algorithmName.contains("SHA256")) {
                    rsapss.put(new SHA2(256, detectionLocation));
                } else if (algorithmName.contains("SHA384")) {
                    rsapss.put(new SHA2(384, detectionLocation));
                } else if (algorithmName.contains("SHA512")) {
                    rsapss.put(new SHA2(512, detectionLocation));
                } else if (algorithmName.contains("SHA1")) {
                    rsapss.put(new SHA(detectionLocation));
                }
                return Optional.of(rsapss);
            }

            // RSA Signatures (PKCS#1 v1.5)
            if (algorithmName.startsWith("RSA-")) {
                RSA rsa = new RSA(Signature.class, detectionLocation);
                if (algorithmName.contains("SHA1")) {
                    rsa.put(new SHA(detectionLocation));
                } else if (algorithmName.contains("SHA224")) {
                    rsa.put(new SHA2(224, detectionLocation));
                } else if (algorithmName.contains("SHA256")) {
                    rsa.put(new SHA2(256, detectionLocation));
                } else if (algorithmName.contains("SHA384")) {
                    rsa.put(new SHA2(384, detectionLocation));
                } else if (algorithmName.contains("SHA512")) {
                    rsa.put(new SHA2(512, detectionLocation));
                }
                return Optional.of(rsa);
            }

            // DSA Signatures
            if (algorithmName.startsWith("DSA-")) {
                if (algorithmName.contains("SHA1")) {
                    return Optional.of(new DSA(new SHA(detectionLocation)));
                } else if (algorithmName.contains("SHA224")) {
                    return Optional.of(new DSA(new SHA2(224, detectionLocation)));
                } else if (algorithmName.contains("SHA256")) {
                    return Optional.of(new DSA(new SHA2(256, detectionLocation)));
                } else if (algorithmName.contains("SHA384")) {
                    return Optional.of(new DSA(new SHA2(384, detectionLocation)));
                } else if (algorithmName.contains("SHA512")) {
                    return Optional.of(new DSA(new SHA2(512, detectionLocation)));
                }
                return Optional.of(new DSA(detectionLocation));
            }

            // ECDSA Signatures
            if (algorithmName.startsWith("ECDSA-")) {
                ECDSA ecdsa = new ECDSA(detectionLocation);
                if (algorithmName.contains("SHA1")) {
                    ecdsa.put(new SHA(detectionLocation));
                } else if (algorithmName.contains("SHA3-256")) {
                    ecdsa.put(new SHA3(256, detectionLocation));
                } else if (algorithmName.contains("SHA3-384")) {
                    ecdsa.put(new SHA3(384, detectionLocation));
                } else if (algorithmName.contains("SHA3-512")) {
                    ecdsa.put(new SHA3(512, detectionLocation));
                } else if (algorithmName.contains("SHA224")) {
                    ecdsa.put(new SHA2(224, detectionLocation));
                } else if (algorithmName.contains("SHA256")) {
                    ecdsa.put(new SHA2(256, detectionLocation));
                } else if (algorithmName.contains("SHA384")) {
                    ecdsa.put(new SHA2(384, detectionLocation));
                } else if (algorithmName.contains("SHA512")) {
                    ecdsa.put(new SHA2(512, detectionLocation));
                }
                return Optional.of(ecdsa);
            }

            // EdDSA Signatures
            if (algorithmName.equals("ED25519") || algorithmName.equals("ED448")) {
                return Optional.of(new EdDSA(detectionLocation));
            }

            // Post-Quantum: ML-DSA
            if (algorithmName.startsWith("ML-DSA-")) {
                if (algorithmName.equals("ML-DSA-44")) {
                    return Optional.of(new MLDSA(2, detectionLocation));
                } else if (algorithmName.equals("ML-DSA-65")) {
                    return Optional.of(new MLDSA(3, detectionLocation));
                } else if (algorithmName.equals("ML-DSA-87")) {
                    return Optional.of(new MLDSA(5, detectionLocation));
                }
            }

            // Post-Quantum: SLH-DSA
            if (algorithmName.startsWith("SLH-DSA-")) {
                return Optional.of(new SLHDSA(detectionLocation));
            }

            // SM2
            if (algorithmName.equals("SM2")) {
                return Optional.of(new SM2(detectionLocation));
            }
        }

        return Optional.empty();
    }
}
