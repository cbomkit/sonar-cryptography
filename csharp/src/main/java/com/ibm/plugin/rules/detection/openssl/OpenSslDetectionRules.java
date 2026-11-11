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
package com.ibm.plugin.rules.detection.openssl;

import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.RuleSets;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

/**
 * Every OpenSSL rule set, and the one property that routes all of them to one translator.
 *
 * <p>OpenSSL reached from C# is not a library with an object model: it is a flat set of {@code
 * static extern} functions whose names are the whole vocabulary. That makes its findings spread
 * across five of the engine's detection contexts -- a cipher, a digest, a MAC, a key, a protocol, a
 * generator -- while sharing one set of constant tables and one notion of what may be reported.
 * Each rule set therefore marks its context with the property {@link #CONTEXT_KEY}, and {@code
 * CSharpTranslator} sends any context carrying that property to {@code
 * CSharpOpenSslContextTranslator} before it looks at the context's class.
 *
 * <p>A separate property rather than the {@code "kind"} the .NET rule sets use, so that nothing
 * here can collide with a {@code kind} the .NET, MailKit, Npgsql or fo-dicom translators already
 * interpret, and so that a reader of {@code CSharpTranslator} sees one line for all of OpenSSL
 * instead of a case added to each of five context translators.
 */
public final class OpenSslDetectionRules extends DetectionRuleSet<CSharpTree> {

    /**
     * The detection-context property that marks a finding as OpenSSL's. Its value says which rule
     * set produced the finding, and {@code CSharpOpenSslContextTranslator} switches on it.
     */
    public static final String CONTEXT_KEY = "openssl";

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return Stream.of(
                        RuleSets.rulesOf(OpenSslTls.class).stream(),
                        RuleSets.rulesOf(OpenSslCipher.class).stream(),
                        RuleSets.rulesOf(OpenSslDigest.class).stream(),
                        RuleSets.rulesOf(OpenSslKey.class).stream(),
                        RuleSets.rulesOf(OpenSslRandom.class).stream())
                .flatMap(i -> i)
                .toList();
    }
}
