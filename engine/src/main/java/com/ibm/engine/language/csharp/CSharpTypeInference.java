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
package com.ibm.engine.language.csharp;

import com.ibm.engine.language.csharp.tree.CSharpArrayCreationTree;
import com.ibm.engine.language.csharp.tree.CSharpBinaryExpressionTree;
import com.ibm.engine.language.csharp.tree.CSharpIdentifierTree;
import com.ibm.engine.language.csharp.tree.CSharpLiteralTree;
import com.ibm.engine.language.csharp.tree.CSharpMemberAccessTree;
import com.ibm.engine.language.csharp.tree.CSharpMethodInvocationTree;
import com.ibm.engine.language.csharp.tree.CSharpObjectCreationTree;
import com.ibm.engine.language.csharp.tree.CSharpScope;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.language.csharp.tree.CSharpVariable;
import java.util.Map;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Infers a syntactic C# type name for an expression tree, purely from the shapes {@code
 * CSharpTreeConverter} produces — no semantic/compiler type information is available.
 *
 * <p>Used by {@code CSharpLanguageTranslation#getMethodParameterTypes} to let {@link
 * com.ibm.engine.detection.MethodMatcher} reject an argument whose type is <em>known and
 * incompatible</em> with a rule's declared parameter type (guard G3 in {@code
 * CSharpDetectionEngine}), while never blocking a match when the type simply cannot be determined —
 * consistent with "no value is better than a wrong one": an unknown type must never cause a false
 * negative, only a known-wrong type may.
 */
final class CSharpTypeInference {

    /**
     * A small table of well-known static/instance calls whose return type is fixed regardless of
     * overload resolution — deliberately tiny; anything not listed here simply infers to {@code
     * null} (unknown), which is always treated as a match.
     */
    @Nonnull
    private static final Map<String, String> KNOWN_RETURN_TYPES =
            Map.of(
                    "RandomNumberGenerator.GetBytes", "byte[]",
                    "UTF8.GetBytes", "byte[]",
                    "ASCII.GetBytes", "byte[]",
                    "Unicode.GetBytes", "byte[]",
                    "Default.GetBytes", "byte[]");

    /**
     * The {@code System.Security.Cryptography} enum, struct and class names that appear as declared
     * parameter types in this rule set. An argument whose inferred type is a C# primitive category
     * ({@code int}, {@code string}, {@code bool}, {@code byte[]}) can never be one of these, which
     * is what makes {@link #isDefinitelyIncompatible} able to discriminate two overloads of equal
     * arity whose parameter layouts differ (e.g. the two five-parameter layouts of {@code
     * Rfc2898DeriveBytes.Pbkdf2}).
     *
     * <p>The list is explicit rather than derived from a naming heuristic so that adding a type is
     * a deliberate, reviewable act. A type that is <em>not</em> listed stays permissive, exactly as
     * {@link #isAssignable} does, so forgetting to add one can only cost precision, never recall.
     */
    @Nonnull
    private static final Set<String> KNOWN_NAMED_TYPES =
            Set.of(
                    "HashAlgorithmName",
                    // fo-dicom's TLS handlers. They are named here so that a string argument
                    // cannot bind to the tlsInitiator parameter of
                    // DicomClientFactory.Create(host, port, ITlsInitiator, callingAe, calledAe):
                    // its sibling overload puts a bool in that position and the two AE titles
                    // after it, so without this the first AE title binds to the initiator and the
                    // connection reads as TLS when it is not.
                    // The concrete classes are named beside the interfaces because the
                    // overload is told apart by position: the bool of the sibling overload sits
                    // where the initiator does, and only a name in this set makes the binder
                    // refuse a DefaultTlsInitiator for a bool. A consumer's own implementation
                    // need not be listed -- it binds at the initiator's own position, and the
                    // only thing this set has to rule out is the bool going there instead.
                    "ITlsInitiator",
                    "ITlsAcceptor",
                    "DefaultTlsInitiator",
                    "DefaultTlsAcceptor",
                    // .NET's TLS version enums. Named here so that the strict side of the type
                    // check can refuse a string or a number for a parameter declared as one:
                    // properties called Protocols or Version exist on all sorts of classes, and
                    // without this a `config.Version = "1.0"` would be reported as a protocol.
                    "SslProtocols",
                    "SecurityProtocolType",
                    // The library-level transport-security switches. MailKit decides TLS with a
                    // SecureSocketOptions argument to Connect and the database drivers with an
                    // SslMode property, and both rules match on an ANY receiver because the client
                    // is held in a variable. Naming the types here is what makes the binder refuse
                    // the bool of MailKit's obsolete Connect overload, and refuse a string for the
                    // SslMode of some unrelated class.
                    "SecureSocketOptions",
                    "SslMode",
                    "ECCurve",
                    "ECParameters",
                    "RSAParameters",
                    "DSAParameters",
                    "RSASignaturePadding",
                    "RSAEncryptionPadding",
                    "RSASignaturePaddingMode",
                    "RSAEncryptionPaddingMode",
                    "PaddingMode",
                    "CipherMode",
                    "DataProtectionScope",
                    "MemoryProtectionScope",
                    "CngAlgorithm",
                    "CngKeyBlobFormat",
                    "CngKeyCreationParameters",
                    "CspParameters",
                    "DSASignatureFormat",
                    "CngKey",
                    "MLKemAlgorithm",
                    "MLDsaAlgorithm",
                    "SlhDsaAlgorithm",
                    "CompositeMLDsaAlgorithm",
                    "KeyDerivationPrf",
                    "ECDiffieHellmanPublicKey",
                    "X509Certificate2",
                    "HashAlgorithm",
                    "SymmetricAlgorithm",
                    "AsymmetricAlgorithm",
                    "RandomNumberGenerator",
                    "DSA",
                    "RSA",
                    "ECDsa",
                    "ECDiffieHellman");

    /**
     * The concrete classes whose interface is known, for the one place that needs a
     * <em>positive</em> answer about a non-primitive type.
     *
     * <p>{@link #isDefinitelyAssignable} otherwise only ever says yes to a type name equal to the
     * declared one or to a primitive of the same category, because there is no semantic model to
     * ask about subtyping. That is enough wherever a parameter binds at its own position, but not
     * where {@link CSharpNamedArgumentBinder} has to search the call for the argument that supplies
     * a parameter -- and the fo-dicom server factory is exactly that case. Its three {@code Create}
     * overloads put {@code ITlsAcceptor} at three different positions, so the acceptor can only be
     * found by type, and the argument written there is a {@code DefaultTlsAcceptor}.
     *
     * <p>Only relations that hold by declaration in the library belong here, and only for
     * interfaces a rule declares as a parameter type, so this can widen the search for nothing
     * else. It cannot cause a wrong binding: the search still requires the match to be unique among
     * the call's arguments.
     */
    @Nonnull
    private static final Map<String, String> KNOWN_IMPLEMENTATIONS =
            Map.of(
                    "DefaultTlsInitiator", "ITlsInitiator",
                    "DefaultTlsAcceptor", "ITlsAcceptor");

    /**
     * The enums and structs of {@link #KNOWN_NAMED_TYPES}, which cannot be subtypes of each other.
     * Two different names from this set are never compatible, for example {@code
     * RSASignaturePadding} and {@code HashAlgorithmName}. The class types ({@code RSA}, {@code
     * AsymmetricAlgorithm}, ...) are left out because one can be a subtype of another.
     */
    @Nonnull
    private static final Set<String> DISJOINT_VALUE_TYPES =
            Set.of(
                    "HashAlgorithmName",
                    "ECCurve",
                    "ECParameters",
                    "RSAParameters",
                    "DSAParameters",
                    "RSASignaturePadding",
                    "RSAEncryptionPadding",
                    "RSASignaturePaddingMode",
                    "RSAEncryptionPaddingMode",
                    "PaddingMode",
                    "CipherMode",
                    "DataProtectionScope",
                    "MemoryProtectionScope",
                    "CngAlgorithm",
                    "CngKeyBlobFormat",
                    "CngKeyCreationParameters",
                    "CspParameters",
                    "DSASignatureFormat",
                    "CngKey",
                    "MLKemAlgorithm",
                    "MLDsaAlgorithm",
                    "SlhDsaAlgorithm",
                    "CompositeMLDsaAlgorithm",
                    "KeyDerivationPrf",
                    "ECDiffieHellmanPublicKey");

    private CSharpTypeInference() {
        // utility
    }

    /**
     * Whether a value of (syntactic) type {@code actual} definitely cannot be passed where {@code
     * expected} is declared.
     *
     * <p>This is the strict counterpart of {@link #isAssignable}, used by {@link
     * CSharpNamedArgumentBinder} to pick the right argument for a declared parameter. The two
     * differ on purpose. {@code isAssignable} feeds {@link com.ibm.engine.detection.MethodMatcher},
     * where a wrong rejection loses the whole detection, so it stays permissive. Here a wrong
     * rejection only means one parameter of an already-detected call is left uncaptured, while a
     * wrong acceptance would attach a value to the wrong parameter — the exact false positive this
     * rule set is built to avoid — so this side may be stricter.
     *
     * <p>Strictness is nonetheless confined to pairs where both sides are recognized: a primitive
     * category against a different primitive category, a primitive category against a name in
     * {@link #KNOWN_NAMED_TYPES}, or two different names in {@link #DISJOINT_VALUE_TYPES}.
     * Everything else is reported as possibly compatible.
     */
    static boolean isDefinitelyIncompatible(@Nonnull String actual, @Nonnull String expected) {
        String a = normalize(actual);
        String e = normalize(expected);
        if (a.equals(e)) {
            return false;
        }
        if (!isAssignable(a, e)) {
            return true;
        }
        if (DISJOINT_VALUE_TYPES.contains(a) && DISJOINT_VALUE_TYPES.contains(e)) {
            return true;
        }
        boolean aPrimitive = isPrimitiveCategory(a);
        boolean ePrimitive = isPrimitiveCategory(e);
        if (aPrimitive && KNOWN_NAMED_TYPES.contains(e)) {
            return true;
        }
        return ePrimitive && KNOWN_NAMED_TYPES.contains(a);
    }

    private static boolean isPrimitiveCategory(@Nonnull String t) {
        return isIntLike(t) || isStringLike(t) || isByteSpanLike(t) || isBoolLike(t);
    }

    /**
     * Whether a value of (syntactic) type {@code actual} is <em>positively known</em> to fit a
     * parameter declared as {@code expected}.
     *
     * <p>This is the third of three strictness levels and the narrowest. {@link #isAssignable}
     * answers "might this fit" and is permissive, {@link #isDefinitelyIncompatible} answers "can
     * this be ruled out", and this one answers "can this be relied upon". It is used only where
     * {@link CSharpNamedArgumentBinder} searches the whole call for the argument that supplies a
     * parameter: there a permissive answer would make every argument a candidate and the uniqueness
     * test that guards the search meaningless.
     */
    static boolean isDefinitelyAssignable(@Nonnull String actual, @Nonnull String expected) {
        String a = normalize(actual);
        String e = normalize(expected);
        if (a.equals(e)) {
            return true;
        }
        if (e.equals(KNOWN_IMPLEMENTATIONS.get(a))) {
            return true;
        }
        return sameCategory(a, e);
    }

    /** Whether both type names fall into the same recognized primitive category. */
    private static boolean sameCategory(@Nonnull String a, @Nonnull String e) {
        if (isIntLike(a)) {
            return isIntLike(e);
        }
        if (isStringLike(a)) {
            return isStringLike(e);
        }
        if (isByteSpanLike(a)) {
            return isByteSpanLike(e);
        }
        return isBoolLike(a) && isBoolLike(e);
    }

    @Nullable static String infer(@Nullable CSharpTree tree) {
        if (tree == null) {
            return null;
        }
        if (tree instanceof CSharpLiteralTree literal) {
            return switch (literal.getKind()) {
                case INTEGER -> "int";
                case REAL -> "double";
                case STRING -> "string";
                case BOOLEAN -> "bool";
                case CHARACTER -> "char";
                case NULL -> null;
            };
        }
        if (tree instanceof CSharpArrayCreationTree array) {
            String elementType = array.getElementType();
            return elementType != null ? elementType + "[]" : null;
        }
        if (tree instanceof CSharpObjectCreationTree creation) {
            return creation.getTypeName();
        }
        if (tree instanceof CSharpMemberAccessTree memberAccess) {
            return memberAccess.getRootType();
        }
        if (tree instanceof CSharpBinaryExpressionTree binary) {
            if ("|".equals(binary.getOperator())) {
                // A flags combination has the type of its members, not of the number behind them:
                // `SslProtocols.Tls12 | SslProtocols.Tls13` is an SslProtocols. Reporting int here
                // would make the strict check refuse the very form these enums are written in.
                String left = infer(binary.getLeft());
                return left != null ? left : infer(binary.getRight());
            }
            return "int"; // only integer arithmetic is folded today
        }
        if (tree instanceof CSharpIdentifierTree identifier) {
            return inferFromScope(identifier);
        }
        if (tree instanceof CSharpMethodInvocationTree invocation) {
            return KNOWN_RETURN_TYPES.get(
                    invocation.getObjectTypeName() + "." + invocation.getMethodName());
        }
        return null;
    }

    @Nullable private static String inferFromScope(@Nonnull CSharpIdentifierTree identifier) {
        CSharpScope scope = identifier.getScope();
        if (scope == null) {
            return null;
        }
        CSharpVariable variable = scope.lookup(identifier.getName());
        if (variable == null) {
            return null;
        }
        if (variable.declaredType() != null) {
            return variable.declaredType();
        }
        return infer(variable.initializer());
    }

    /**
     * Whether a value of (syntactic) type {@code actual} may be passed where {@code expected} is
     * declared. Deliberately permissive: only rejects combinations that are unambiguously
     * incompatible in C# (e.g. {@code string} where {@code int} is expected); anything not
     * recognized is treated as compatible, since a false rejection would silently drop a detection
     * (a worse outcome than the rare false acceptance of an unusual conversion).
     */
    static boolean isAssignable(@Nonnull String actual, @Nonnull String expected) {
        String a = normalize(actual);
        String e = normalize(expected);
        if (a.equals(e)) {
            return true;
        }
        if (isByteSpanLike(a) && isByteSpanLike(e)) {
            return true;
        }
        if (isIntLike(a) && isIntLike(e)) {
            return true;
        }
        if (isStringLike(a) && isStringLike(e)) {
            return true;
        }
        // Different, recognized, non-overlapping categories (e.g. "string" vs "int",
        // "HashAlgorithmName" vs "int") — this is the one case we actively reject.
        boolean aKnownCategory =
                isIntLike(a) || isStringLike(a) || isByteSpanLike(a) || isBoolLike(a);
        boolean eKnownCategory =
                isIntLike(e) || isStringLike(e) || isByteSpanLike(e) || isBoolLike(e);
        // At least one side is an unrecognized (likely enum/struct/class) type name — different
        // spellings could still be the same type via `using` aliases or nesting we cannot see, so
        // stay permissive rather than risk a false negative.
        return !aKnownCategory || !eKnownCategory;
    }

    @Nonnull
    private static String normalize(@Nonnull String type) {
        String t = type.trim();
        int lt = t.indexOf('<');
        if (lt > 0) {
            t = t.substring(0, lt);
        }
        return t;
    }

    private static boolean isIntLike(@Nonnull String t) {
        return switch (t) {
            case "int",
                    "Int32",
                    "long",
                    "Int64",
                    "short",
                    "Int16",
                    "byte",
                    "Byte",
                    "uint",
                    "UInt32" ->
                    true;
            default -> false;
        };
    }

    private static boolean isStringLike(@Nonnull String t) {
        return t.equals("string") || t.equals("String");
    }

    private static boolean isBoolLike(@Nonnull String t) {
        return t.equals("bool") || t.equals("Boolean");
    }

    private static boolean isByteSpanLike(@Nonnull String t) {
        return t.equals("byte[]")
                || t.equals("Byte[]")
                || t.equals("Span")
                || t.equals("ReadOnlySpan")
                || t.equals("Memory")
                || t.equals("ReadOnlyMemory");
    }
}
