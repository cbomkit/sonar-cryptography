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
import com.ibm.engine.model.context.DetectionContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.mapper.openssl.OpenSslMessageDigestMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.MGF1;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.utils.DetectionLocation;
import com.sonar.cxx.sslr.api.AstNode;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class CxxDigestContextTranslator implements IContextTranslation<AstNode> {

    /** The property of a digest context that tells what the digest is used for. */
    public static final String KIND = "kind";

    /** The kind of the digest of a mask generation function. */
    public static final String MGF1_KIND = "MGF1";

    /** The kind of the digest of RSA-OAEP. */
    public static final String OAEP_KIND = "OAEP";

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<AstNode> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<AstNode> || value instanceof Algorithm<AstNode>) {
            final Optional<INode> digest =
                    new OpenSslMessageDigestMapper()
                            .parse(value.asString(), detectionLocation)
                            .map(node -> node);
            // the digest of a mask generation function, e.g. the MGF1 digest of RSA-PSS or
            // RSA-OAEP, is reported as that function
            if (detectionContext instanceof DetectionContext context
                    && context.get(KIND).filter(MGF1_KIND::equals).isPresent()) {
                return digest.filter(MessageDigest.class::isInstance)
                        .map(node -> new MGF1((MessageDigest) node));
            }
            // the digest of RSA-OAEP, given by name to EVP_PKEY_CTX_set_rsa_oaep_md_name
            if (detectionContext instanceof DetectionContext context
                    && context.get(KIND).filter(OAEP_KIND::equals).isPresent()) {
                return digest.filter(MessageDigest.class::isInstance)
                        .map(node -> new OAEP((MessageDigest) node, detectionLocation));
            }
            return digest;
        }

        return Optional.empty();
    }
}
