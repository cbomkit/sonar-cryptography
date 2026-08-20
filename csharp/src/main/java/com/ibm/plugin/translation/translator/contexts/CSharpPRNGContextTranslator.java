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
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.IContextTranslation;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.model.functionality.Generate;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Translates {@link com.ibm.engine.model.context.PRNGContext} detections for .NET APIs ({@code
 * RandomNumberGenerator}, {@code RNGCryptoServiceProvider} — see {@link
 * com.ibm.plugin.rules.detection.dotnet.DotNetRandomNumberGenerator}).
 *
 * <p>Mirrors {@code GoPRNGContextTranslator}: .NET's {@code RandomNumberGenerator} is
 * architecturally the same shape as Go's {@code crypto/rand} (ask the platform for
 * cryptographically strong random output, no user-selectable algorithm), so the same {@code
 * "NATIVEPRNG"} {@link Algorithm} identity is reused instead of introducing a new mapper model
 * class.
 */
public final class CSharpPRNGContextTranslator implements IContextTranslation<CSharpTree> {

    @Override
    public @Nonnull Optional<INode> translate(
            @Nonnull IBundle bundleIdentifier,
            @Nonnull IValue<CSharpTree> value,
            @Nonnull IDetectionContext detectionContext,
            @Nonnull DetectionLocation detectionLocation) {

        if (value instanceof ValueAction<?>) {
            return switch (value.asString().toUpperCase().trim()) {
                // RandomNumberGenerator.Create()/Create(string), every static self-contained
                // method (Fill/GetBytes/GetHexString/GetInt32/GetItems/GetNonZeroBytes/
                // GetString/Shuffle), and the RNGCryptoServiceProvider constructor all identify
                // the same underlying platform CSPRNG.
                case "NATIVEPRNG" ->
                        Optional.of(
                                new Algorithm(
                                        "NATIVEPRNG",
                                        PseudorandomNumberGenerator.class,
                                        detectionLocation));
                // Instance operations on an already-identified RNG object
                // (RandomNumberGenerator.Create()'s or RNGCryptoServiceProvider's
                // GetBytes/GetNonZeroBytes) — the RNG identity is already captured by the parent
                // node, so these depending calls only need to record that a generate operation
                // happened (mirrors GenerateIV in CSharpCipherContextTranslator, which has no
                // more specific CipherAction available either).
                case "GETBYTES", "GETNONZEROBYTES" -> Optional.of(new Generate(detectionLocation));
                default -> Optional.empty();
            };
        }

        return Optional.empty();
    }
}
