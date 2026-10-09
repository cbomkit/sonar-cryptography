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
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.openssl.OpenSslMessageDigestMapper;
import com.ibm.mapper.mapper.openssl.OpenSslSignatureAlgorithmMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.algorithms.MGF1;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.model.functionality.Verify;
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

    /** The property of a signature context that tells what its values are. */
    public static final String KIND = "kind";

    /** The kind of a signature context whose algorithm values are the digest names it uses. */
    public static final String DIGEST_NAME_KIND = "DIGEST_NAME";

    /**
     * The kind of a signature context whose algorithm values are the names of the digests of the
     * MGF1 mask generation function it uses.
     */
    public static final String MGF1_DIGEST_NAME_KIND = "MGF1_DIGEST_NAME";

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull DetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof SignatureAction<AstNode> signatureAction) {
            return switch (signatureAction.getAction()) {
                case SIGN -> Optional.of(new Sign(detectionLocation));
                case VERIFY -> Optional.of(new Verify(detectionLocation));
            };
        }

        if (value instanceof SaltSize<AstNode> saltSize) {
            // a negative salt length selects a length derived from the digest or the key
            return saltSize.getValue() > 0
                    ? Optional.of(new SaltLength(saltSize.getValue(), detectionLocation))
                    : Optional.empty();
        }

        // the digest of a digest sign or verify operation given by name, e.g. the mdname of
        // EVP_DigestSignInit_ex
        if (value instanceof Algorithm<AstNode>
                && detectionContext instanceof DetectionContext context
                && context.get(KIND).filter(DIGEST_NAME_KIND::equals).isPresent()) {
            return new OpenSslMessageDigestMapper()
                    .parse(value.asString(), detectionLocation)
                    .map(node -> node);
        }

        // the digest of the MGF1 mask generation function given by name, e.g. the mdname of
        // EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name
        if (value instanceof Algorithm<AstNode>
                && detectionContext instanceof DetectionContext context
                && context.get(KIND).filter(MGF1_DIGEST_NAME_KIND::equals).isPresent()) {
            return new OpenSslMessageDigestMapper()
                    .parse(value.asString(), detectionLocation)
                    .filter(MessageDigest.class::isInstance)
                    .map(digest -> new MGF1((MessageDigest) digest));
        }

        if (value instanceof ValueAction<AstNode> || value instanceof Algorithm<AstNode>) {
            return new OpenSslSignatureAlgorithmMapper()
                    .parse(value.asString(), detectionLocation)
                    .map(node -> node);
        }

        return Optional.empty();
    }
}
