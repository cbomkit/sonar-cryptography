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

import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.RIPEMD;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.shake.SHAKE;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/** Translates {@link com.ibm.engine.model.context.DigestContext} detections for .NET APIs. */
public final class CSharpDigestContextTranslator implements IContextTranslation<CSharpTree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<CSharpTree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<?>) {
            return switch (value.asString().toUpperCase().trim()) {
                case "SHA1" -> Optional.of(new SHA(detectionLocation));
                case "SHA256" -> Optional.of(new SHA2(256, detectionLocation));
                case "SHA384" -> Optional.of(new SHA2(384, detectionLocation));
                case "SHA512" -> Optional.of(new SHA2(512, detectionLocation));
                case "MD5" -> Optional.of(new MD5(detectionLocation));
                case "RIPEMD160" -> Optional.of(new RIPEMD(160, detectionLocation));
                case "SHA3_256" -> Optional.of(new SHA3(256, detectionLocation));
                case "SHA3_384" -> Optional.of(new SHA3(384, detectionLocation));
                case "SHA3_512" -> Optional.of(new SHA3(512, detectionLocation));
                case "SHAKE128" -> Optional.of(new SHAKE(128, detectionLocation));
                case "SHAKE256" -> Optional.of(new SHAKE(256, detectionLocation));
                default -> Optional.empty();
            };
        } else if (value instanceof Algorithm<?>) {
            // HashAlgorithm.Create(string) — string table verified against the official API
            // reference (learn.microsoft.com), see DotNetAlgorithmFactory javadoc. Unlike the
            // ValueAction branch above (fixed per-class identity), the concrete digest here is
            // resolved purely from the captured runtime string.
            return switch (value.asString().toUpperCase().trim()) {
                case "SHA",
                        "SHA1",
                        "SYSTEM.SECURITY.CRYPTOGRAPHY.SHA1",
                        "SYSTEM.SECURITY.CRYPTOGRAPHY.HASHALGORITHM" ->
                        Optional.of(new SHA(detectionLocation));
                case "MD5", "SYSTEM.SECURITY.CRYPTOGRAPHY.MD5" ->
                        Optional.of(new MD5(detectionLocation));
                case "SHA256", "SHA-256", "SYSTEM.SECURITY.CRYPTOGRAPHY.SHA256" ->
                        Optional.of(new SHA2(256, detectionLocation));
                case "SHA384", "SHA-384", "SYSTEM.SECURITY.CRYPTOGRAPHY.SHA384" ->
                        Optional.of(new SHA2(384, detectionLocation));
                case "SHA512", "SHA-512", "SYSTEM.SECURITY.CRYPTOGRAPHY.SHA512" ->
                        Optional.of(new SHA2(512, detectionLocation));
                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
