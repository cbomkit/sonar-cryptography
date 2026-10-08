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
package com.ibm.plugin.rules.detection.dotnet;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.IterationCountFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.SaltSizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for PBKDF2 via {@code Rfc2898DeriveBytes} in System.Security.Cryptography.
 *
 * <p>Captures the three parameters that decide whether a password-based derivation is sound — the
 * iteration count, the salt length and the pseudo-random function — plus the length of the derived
 * key where the call states it.
 *
 * <h2>Overloads covered</h2>
 *
 * <p>Constructors, nine in total per the official API reference, spanning arities two to four:
 *
 * <ul>
 *   <li>{@code (byte[] password, byte[] salt)}, {@code (string password, byte[] salt)}, {@code
 *       (string password, int saltSize)}
 *   <li>the same three with a trailing {@code int iterations}
 *   <li>the same three again with a further trailing {@code HashAlgorithmName hashAlgorithm}
 * </ul>
 *
 * <p>All nine are {@code Obsolete} as of net-10.0 in favour of the static {@code Pbkdf2}, but they
 * remain valid, widely deployed and therefore worth detecting. Position one is {@code salt} in six
 * of them and {@code saltSize} in three; both denote a salt length in bytes, so a single {@code
 * SaltSizeFactory} in byte units reads either correctly — a {@code byte[]} argument through its
 * array length, an {@code int} argument directly.
 *
 * <p>The static {@code Pbkdf2}, six overloads, all of arity five, in two different layouts: four
 * are {@code (password, salt, iterations, hashAlgorithm, outputLength)} and two are {@code
 * (password, salt, destination, iterations, hashAlgorithm)}. The two layouts disagree on positions
 * two, three and four, which no arity-based matcher can separate. They are separated instead by the
 * declared parameter types: {@code int} and {@code HashAlgorithmName} cannot be confused for one
 * another, so the binder's type-directed step places {@code iterations} and {@code hashAlgorithm}
 * correctly in both layouts (see {@code CSharpNamedArgumentBinder}). In the second layout {@code
 * outputLength} has no counterpart, so it is simply left uncaptured; the derived length is carried
 * by the {@code destination} span, which is not a value this engine can measure.
 *
 * <h2>One rule per method</h2>
 *
 * <p>Each method is covered by exactly one rule whose parameter list is the positional union of its
 * overloads, with only the parameters common to every overload declared as required and the rest
 * optional. Because a rule that declares named parameters is matched without an arity constraint,
 * this one rule accepts every overload, and because it is the only rule for that method no call can
 * be detected twice. The alternative, one rule per arity, would need the parameter list to be
 * exactly right for each arity and would silently drop any arity that was overlooked.
 *
 * <p>{@code password} is declared but never captured. A password length is not a property of the
 * derivation, and for the {@code string} overloads it would be the length of a hardcoded literal,
 * which belongs to a secret-detection rule rather than to a bill of materials.
 *
 * <h2>Instance operations</h2>
 *
 * <p>{@code GetBytes(int cb)} pulls {@code cb} bytes of derived key material, which is the derived
 * key length and is captured as such. {@code CryptDeriveKey(string algname, string alghashname, int
 * keySize, byte[] rgbIV)} is the CAPI-style derivation; its cipher name, hash name and key size are
 * all captured. Both are also {@code Obsolete} and both are modelled as depending rules on the
 * constructor, so their values attach to the {@code PBKDF2} node the constructor produced.
 */
@SuppressWarnings("java:S1192")
public final class DotNetRfc2898DeriveBytes extends DetectionRuleSet<CSharpTree> {

    // =========================================================================
    // Instance operation depending rules
    // =========================================================================

    // instance.GetBytes(cb) — cb bytes of derived key material
    private static final IDetectionRule<CSharpTree> RFC2898_GET_BYTES =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("GetBytes")
                    .shouldBeDetectedAs(new ValueActionFactory<>("GetBytes"))
                    .withNamedMethodParameter("cb", "int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "KDF_RFC2898_GET_BYTES")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // instance.CryptDeriveKey(algname, algHashName, keySize, rgbIV)
    private static final IDetectionRule<CSharpTree> RFC2898_CRYPT_DERIVE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("CryptDeriveKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("CryptDeriveKey"))
                    .withNamedMethodParameter("algname", "string")
                    .withNamedMethodParameter("alghashname", "string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withNamedMethodParameter("keySize", "int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .withNamedMethodParameter("rgbIV", MethodMatcher.ANY)
                    .buildForContext(new KeyContext(Map.of("kind", "KDF_RFC2898_CRYPT_DERIVE_KEY")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<CSharpTree>> RFC2898_DEPENDING_RULES =
            List.of(RFC2898_GET_BYTES, RFC2898_CRYPT_DERIVE_KEY);

    // =========================================================================
    // Primary rules
    // =========================================================================

    // new Rfc2898DeriveBytes(password, salt|saltSize [, iterations [, hashAlgorithm]])
    private static final IDetectionRule<CSharpTree> RFC2898 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("Rfc2898DeriveBytes")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withNamedMethodParameter("password", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("salt", MethodMatcher.ANY)
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("iterations", "int")
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "KDF")))
                    .inBundle(() -> "DotNet")
                    .withDependingDetectionRules(RFC2898_DEPENDING_RULES);

    // Rfc2898DeriveBytes.Pbkdf2(...) — static one-shot, both five-parameter layouts
    private static final IDetectionRule<CSharpTree> RFC2898_PBKDF2_STATIC =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("Rfc2898DeriveBytes")
                    .forMethods("Pbkdf2")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PBKDF2"))
                    .withNamedMethodParameter("password", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("salt", MethodMatcher.ANY)
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("iterations", "int")
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("outputLength", "int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new KeyContext(Map.of("kind", "KDF")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(RFC2898, RFC2898_PBKDF2_STATIC);
    }
}
