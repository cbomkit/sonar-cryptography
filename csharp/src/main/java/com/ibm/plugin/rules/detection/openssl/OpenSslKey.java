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

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.IterationCountFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.ParameterIdentifierFactory;
import com.ibm.engine.model.factory.SaltSizeFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * OpenSSL's asymmetric key generation, RSA padding and password-based key derivation.
 *
 * <h2>Key generation</h2>
 *
 * <p>Unlike the symmetric side, these calls do name the algorithm -- in the function name for the
 * RSA, DSA, DH and EC entry points, and in a string argument for {@code EVP_PKEY_Q_keygen}. The
 * size or the curve sits beside it in the same call, so each finding is one component with its
 * parameter attached:
 *
 * <ul>
 *   <li>{@code RSA_generate_key_ex(rsa, 4096, e, cb)} and {@code EVP_RSA_gen(3072)} -- RSA with its
 *       modulus size. {@code RSA_generate_key} (deprecated in 0.9.8) and {@code
 *       RSA_generate_multi_prime_key} are read the same way; the number of primes is not recorded,
 *       because the mapper has nothing to put it in.
 *   <li>{@code EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048)} -- the 3.x way to say the same thing.
 *       The function name is what states RSA; the context it is called on is opaque here.
 *   <li>{@code EVP_PKEY_CTX_set_dsa_paramgen_bits} and {@code
 *       EVP_PKEY_CTX_set_dh_paramgen_prime_len} -- DSA and Diffie-Hellman with their prime length.
 *   <li>{@code EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1)} and {@code
 *       EVP_PKEY_CTX_set_group_name(ctx, "P-256")} -- an EC key on a named curve. Here the curve
 *       <em>is</em> the finding and no action is declared, so the component is {@code EC-secp384r1}
 *       rather than a bare {@code EC} with a property hanging off it. A NID resolves from the
 *       constant's name or from its numeric value, both of which {@link OpenSslApi} holds; a number
 *       that is not a curve NID resolves to nothing.
 *   <li>{@code EVP_PKEY_Q_keygen(libctx, propq, "RSA", 4096)} -- the 3.0 shorthand. The type string
 *       is the component and the one variadic argument is its parameter: the man page says a {@code
 *       size_t} for {@code "RSA"} and a curve-name string for {@code "EC"}, so a number becomes the
 *       key length and a recognised curve name becomes the curve. Anything else is dropped.
 * </ul>
 *
 * <p>{@code EVP_PKEY_keygen(ctx, &pkey)} and {@code EVP_PKEY_generate} are deliberately not rules.
 * They name neither algorithm nor size -- both were set on the {@code EVP_PKEY_CTX} earlier, and
 * the {@code EVP_PKEY_CTX_set_*} rules above are what read them. A rule there could only produce a
 * component with no identity.
 *
 * <h2>Padding</h2>
 *
 * <p>{@code EVP_PKEY_CTX_set_rsa_padding} and the four {@code RSA_*_encrypt}/{@code *_decrypt}
 * functions each carry one of the {@code RSA_*_PADDING} constants, by name or by value -- the
 * values are part of OpenSSL's ABI and have not changed since 0.9.x. The four raw functions also
 * state the direction, which is why they are four rules rather than one: {@code RSA_public_encrypt}
 * encrypts, {@code RSA_private_decrypt} decrypts, and the pair {@code RSA_private_encrypt} / {@code
 * RSA_public_decrypt} is the raw signature primitive.
 *
 * <h2>Password-based derivation</h2>
 *
 * <p>{@code PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, digest, keylen, out)} is the call
 * this rule set exists for. It yields PBKDF2 with the iteration count, the salt length and the
 * derived key length -- the three numbers an auditor reads a PBKDF2 call site for. The salt length
 * is taken from {@code saltlen} rather than from the {@code salt} buffer, because the buffer is
 * usually a parameter and the length is usually a literal, and the key length is taken as bytes and
 * reported in bits, which is what {@code KeySizeFactory} is told.
 *
 * <p>The digest at index 5 is <em>not</em> read: it arrives as {@code EVP_sha256()}, a call rather
 * than a value, and that call is already a digest finding of its own on the same line. {@code
 * PKCS5_PBKDF2_HMAC_SHA1} is the exception -- its name states SHA-1, so that one does report {@code
 * PBKDF2-SHA-1} as a single component.
 *
 * <p>{@code EVP_PBE_scrypt} reports scrypt with its salt and key lengths. Its {@code N}, {@code r}
 * and {@code p} cost parameters are not recorded: the mapper's model has no field for them, {@code
 * NumberOfIterations} is not what {@code N} is, and a work factor written into the wrong field is
 * worse than one left out.
 */
public final class OpenSslKey extends DetectionRuleSet<CSharpTree> {

    public static final String RSA = "RSA";
    public static final String DSA = "DSA";
    public static final String DH = "DH";
    public static final String RSA_ENCRYPT = "RSA_ENCRYPT";
    public static final String RSA_DECRYPT = "RSA_DECRYPT";
    public static final String RSA_SIGN = "RSA_SIGN";
    public static final String RSA_VERIFY = "RSA_VERIFY";
    public static final String PBKDF2 = "PBKDF2";
    public static final String PBKDF2_SHA1 = "PBKDF2_SHA1";
    public static final String SCRYPT = "SCRYPT";

    private static final String KEYGEN = "KEYGEN";
    private static final String PADDING = "PADDING";
    private static final String KDF = "KDF";

    @Nonnull
    private static KeyContext context(@Nonnull String kind) {
        return new KeyContext(Map.of(OpenSslDetectionRules.CONTEXT_KEY, kind));
    }

    // =====================================================================
    // RSA / DSA / DH key generation
    // =====================================================================

    /** {@code RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)}. */
    private static final IDetectionRule<CSharpTree> RSA_GENERATE_KEY_EX =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("RSA_generate_key_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>(RSA))
                    .withMethodParameter(MethodMatcher.ANY) // rsa
                    .withMethodParameter("int") // bits
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // e
                    .withMethodParameter(MethodMatcher.ANY) // cb
                    .buildForContext(context(KEYGEN))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /**
     * {@code RSA_generate_multi_prime_key(RSA *rsa, int bits, int primes, BIGNUM *e, BN_GENCB
     * *cb)}.
     */
    private static final IDetectionRule<CSharpTree> RSA_GENERATE_MULTI_PRIME_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("RSA_generate_multi_prime_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>(RSA))
                    .withMethodParameter(MethodMatcher.ANY) // rsa
                    .withMethodParameter("int") // bits
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // primes
                    .withMethodParameter(MethodMatcher.ANY) // e
                    .withMethodParameter(MethodMatcher.ANY) // cb
                    .buildForContext(context(KEYGEN))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /** {@code RSA_generate_key(int bits, unsigned long e, callback, void *cb_arg)}. */
    private static final IDetectionRule<CSharpTree> RSA_GENERATE_KEY =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("RSA_generate_key")
                    .shouldBeDetectedAs(new ValueActionFactory<>(RSA))
                    .withMethodParameter("int") // bits
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // e
                    .withMethodParameter(MethodMatcher.ANY) // callback
                    .withMethodParameter(MethodMatcher.ANY) // cb_arg
                    .buildForContext(context(KEYGEN))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /** {@code EVP_RSA_gen(unsigned int bits)} -- the 3.0 one-liner. */
    private static final IDetectionRule<CSharpTree> EVP_RSA_GEN =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_RSA_gen")
                    .shouldBeDetectedAs(new ValueActionFactory<>(RSA))
                    .withMethodParameter("int") // bits
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(context(KEYGEN))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /** {@code EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *ctx, int mbits)}. */
    private static final IDetectionRule<CSharpTree> RSA_KEYGEN_BITS =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_PKEY_CTX_set_rsa_keygen_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>(RSA))
                    .withMethodParameter(MethodMatcher.ANY) // ctx
                    .withMethodParameter("int") // mbits
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(context(KEYGEN))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /** {@code EVP_PKEY_CTX_set_dsa_paramgen_bits(EVP_PKEY_CTX *ctx, int nbits)}. */
    private static final IDetectionRule<CSharpTree> DSA_PARAMGEN_BITS =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_PKEY_CTX_set_dsa_paramgen_bits")
                    .shouldBeDetectedAs(new ValueActionFactory<>(DSA))
                    .withMethodParameter(MethodMatcher.ANY) // ctx
                    .withMethodParameter("int") // nbits
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(context(KEYGEN))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /** {@code EVP_PKEY_CTX_set_dh_paramgen_prime_len(EVP_PKEY_CTX *ctx, int len)}. */
    private static final IDetectionRule<CSharpTree> DH_PARAMGEN_PRIME_LEN =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_PKEY_CTX_set_dh_paramgen_prime_len")
                    .shouldBeDetectedAs(new ValueActionFactory<>(DH))
                    .withMethodParameter(MethodMatcher.ANY) // ctx
                    .withMethodParameter("int") // len
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(context(KEYGEN))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /**
     * {@code EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid)}.
     *
     * <p>No action: the curve is the whole finding, and an unrecognised NID has to leave the call
     * silent rather than produce a curveless {@code EC}.
     */
    private static final IDetectionRule<CSharpTree> EC_PARAMGEN_CURVE_NID =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
                    .withMethodParameter(MethodMatcher.ANY) // ctx
                    .withMethodParameter("int") // nid
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .buildForContext(context("EC_CURVE_NID"))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /** {@code EVP_PKEY_CTX_set_group_name(EVP_PKEY_CTX *ctx, const char *name)}. */
    private static final IDetectionRule<CSharpTree> EC_GROUP_NAME =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_PKEY_CTX_set_group_name")
                    .withMethodParameter(MethodMatcher.ANY) // ctx
                    .withMethodParameter("string") // name
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .buildForContext(context("EC_CURVE_NAME"))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /**
     * {@code EVP_PKEY_Q_keygen(OSSL_LIB_CTX *libctx, const char *propq, const char *type, ...)}.
     *
     * <p>Named parameters, so the arity band is {@code [3, 4]} -- the three fixed parameters plus
     * the one variadic argument the man page describes for {@code "RSA"} and {@code "EC"}. The type
     * string is the root of the finding, and the variadic argument is attached under it with {@code
     * asChildOfParameterWithId(2)}, which names the <em>type</em> parameter's index rather than the
     * usual {@code -1}: there is no action to be a child of, because the algorithm is not knowable
     * from the method name.
     */
    private static final IDetectionRule<CSharpTree> PKEY_Q_KEYGEN =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_PKEY_Q_keygen")
                    .withNamedMethodParameter("libctx", MethodMatcher.ANY)
                    .withNamedMethodParameter("propq", MethodMatcher.ANY)
                    .withNamedMethodParameter("type", "string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withOptionalNamedMethodParameter("param", MethodMatcher.ANY)
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(2)
                    .buildForContext(context("PKEY_Q_KEYGEN"))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    // =====================================================================
    // RSA padding
    // =====================================================================

    /** {@code EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad)}. */
    private static final IDetectionRule<CSharpTree> RSA_PADDING =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_PKEY_CTX_set_rsa_padding")
                    .shouldBeDetectedAs(new ValueActionFactory<>(RSA))
                    .withMethodParameter(MethodMatcher.ANY) // ctx
                    .withMethodParameter("int") // pad
                    .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(context(PADDING))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    @Nonnull
    private static IDetectionRule<CSharpTree> rawRsaOperation(
            @Nonnull String methodName, @Nonnull String action) {
        return new DetectionRuleBuilder<CSharpTree>()
                .createDetectionRule()
                .forObjectTypes(MethodMatcher.ANY)
                .forMethods(methodName)
                .shouldBeDetectedAs(new ValueActionFactory<>(action))
                .withMethodParameter(MethodMatcher.ANY) // flen
                .withMethodParameter(MethodMatcher.ANY) // from
                .withMethodParameter(MethodMatcher.ANY) // to
                .withMethodParameter(MethodMatcher.ANY) // rsa
                .withMethodParameter("int") // padding
                .shouldBeDetectedAs(new ParameterIdentifierFactory<>())
                .asChildOfParameterWithId(-1)
                .buildForContext(context(PADDING))
                .inBundle(() -> "OpenSsl")
                .withoutDependingDetectionRules();
    }

    // =====================================================================
    // Password-based key derivation
    // =====================================================================

    /**
     * {@code PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, digest, keylen, out)}.
     *
     * <p>Eight positional parameters, which is also what separates this from the seven-parameter
     * {@code PKCS5_PBKDF2_HMAC_SHA1} rule.
     */
    private static final IDetectionRule<CSharpTree> PKCS5_PBKDF2_HMAC =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("PKCS5_PBKDF2_HMAC")
                    .shouldBeDetectedAs(new ValueActionFactory<>(PBKDF2))
                    .withMethodParameter(MethodMatcher.ANY) // pass
                    .withMethodParameter(MethodMatcher.ANY) // passlen
                    .withMethodParameter(MethodMatcher.ANY) // salt
                    .withMethodParameter("int") // saltlen
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int") // iter
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // digest
                    .withMethodParameter("int") // keylen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // out
                    .buildForContext(context(KDF))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /** {@code PKCS5_PBKDF2_HMAC_SHA1(pass, passlen, salt, saltlen, iter, keylen, out)}. */
    private static final IDetectionRule<CSharpTree> PKCS5_PBKDF2_HMAC_SHA1 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("PKCS5_PBKDF2_HMAC_SHA1")
                    .shouldBeDetectedAs(new ValueActionFactory<>(PBKDF2_SHA1))
                    .withMethodParameter(MethodMatcher.ANY) // pass
                    .withMethodParameter(MethodMatcher.ANY) // passlen
                    .withMethodParameter(MethodMatcher.ANY) // salt
                    .withMethodParameter("int") // saltlen
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int") // iter
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter("int") // keylen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // out
                    .buildForContext(context(KDF))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /**
     * {@code EVP_PBE_scrypt(pass, passlen, salt, saltlen, N, r, p, maxmem, key, keylen)}.
     *
     * <p>Ten positional parameters. {@code EVP_PBE_scrypt_ex} adds a library context and a property
     * query and is a rule of its own for that reason.
     */
    private static final IDetectionRule<CSharpTree> EVP_PBE_SCRYPT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_PBE_scrypt")
                    .shouldBeDetectedAs(new ValueActionFactory<>(SCRYPT))
                    .withMethodParameter(MethodMatcher.ANY) // pass
                    .withMethodParameter(MethodMatcher.ANY) // passlen
                    .withMethodParameter(MethodMatcher.ANY) // salt
                    .withMethodParameter("int") // saltlen
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // N
                    .withMethodParameter(MethodMatcher.ANY) // r
                    .withMethodParameter(MethodMatcher.ANY) // p
                    .withMethodParameter(MethodMatcher.ANY) // maxmem
                    .withMethodParameter(MethodMatcher.ANY) // key
                    .withMethodParameter("int") // keylen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .buildForContext(context(KDF))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /**
     * {@code EVP_PBE_scrypt_ex(pass, passlen, salt, saltlen, N, r, p, maxmem, key, keylen, ctx,
     * propq)} -- the same with a library context and a property query, so twelve parameters.
     */
    private static final IDetectionRule<CSharpTree> EVP_PBE_SCRYPT_EX =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_PBE_scrypt_ex")
                    .shouldBeDetectedAs(new ValueActionFactory<>(SCRYPT))
                    .withMethodParameter(MethodMatcher.ANY) // pass
                    .withMethodParameter(MethodMatcher.ANY) // passlen
                    .withMethodParameter(MethodMatcher.ANY) // salt
                    .withMethodParameter("int") // saltlen
                    .shouldBeDetectedAs(new SaltSizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // N
                    .withMethodParameter(MethodMatcher.ANY) // r
                    .withMethodParameter(MethodMatcher.ANY) // p
                    .withMethodParameter(MethodMatcher.ANY) // maxmem
                    .withMethodParameter(MethodMatcher.ANY) // key
                    .withMethodParameter("int") // keylen
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BYTE))
                    .asChildOfParameterWithId(-1)
                    .withMethodParameter(MethodMatcher.ANY) // ctx
                    .withMethodParameter(MethodMatcher.ANY) // propq
                    .buildForContext(context(KDF))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    /** {@code EVP_KDF_fetch(OSSL_LIB_CTX *libctx, const char *algorithm, const char *props)}. */
    private static final IDetectionRule<CSharpTree> EVP_KDF_FETCH =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("EVP_KDF_fetch")
                    .withMethodParameter(MethodMatcher.ANY) // libctx
                    .withMethodParameter("string") // algorithm
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(MethodMatcher.ANY) // properties
                    .buildForContext(context("KDF_FETCH"))
                    .inBundle(() -> "OpenSsl")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(
                RSA_GENERATE_KEY_EX,
                RSA_GENERATE_MULTI_PRIME_KEY,
                RSA_GENERATE_KEY,
                EVP_RSA_GEN,
                RSA_KEYGEN_BITS,
                DSA_PARAMGEN_BITS,
                DH_PARAMGEN_PRIME_LEN,
                EC_PARAMGEN_CURVE_NID,
                EC_GROUP_NAME,
                PKEY_Q_KEYGEN,
                RSA_PADDING,
                rawRsaOperation("RSA_public_encrypt", RSA_ENCRYPT),
                rawRsaOperation("RSA_private_decrypt", RSA_DECRYPT),
                rawRsaOperation("RSA_private_encrypt", RSA_SIGN),
                rawRsaOperation("RSA_public_decrypt", RSA_VERIFY),
                PKCS5_PBKDF2_HMAC,
                PKCS5_PBKDF2_HMAC_SHA1,
                EVP_PBE_SCRYPT,
                EVP_PBE_SCRYPT_EX,
                EVP_KDF_FETCH);
    }
}
