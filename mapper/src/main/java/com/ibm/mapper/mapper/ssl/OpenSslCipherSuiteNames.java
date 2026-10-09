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
package com.ibm.mapper.mapper.ssl;

import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * The OpenSSL names of the TLS cipher suites for which the cipher suite data ({@code
 * ciphersuites.json}, from ciphersuite.info) gives no OpenSSL name, by the IANA name of the suite.
 * These are suites that OpenSSL 1.0.2 and 1.1.1 define, or that OpenSSL 3.0 defines but leaves out
 * of the build by default, e.g. the RC4, DES, export, Kerberos, static DH and static ECDH suites.
 * The names and their codes are those of {@code SSLn_TXT_*} / {@code TLS1_TXT_*} and {@code
 * SSLn_CK_*} / {@code TLS1_CK_*} in OpenSSL's {@code ssl3.h} and {@code tls1.h}; both spellings of
 * the ephemeral DH suites ({@code EDH-} and {@code DHE-}) are accepted, as OpenSSL does. The
 * Fortezza name {@code FZA-RC4-SHA} of code 0x001E, which IANA assigns to {@code
 * TLS_KRB5_WITH_DES_CBC_SHA}, is left out.
 */
final class OpenSslCipherSuiteNames {

    private static final Map<String, String> IANA_NAMES =
            Map.ofEntries(
                    Map.entry("EXP-RC4-MD5", "TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
                    Map.entry("RC4-MD5", "TLS_RSA_WITH_RC4_128_MD5"),
                    Map.entry("RC4-SHA", "TLS_RSA_WITH_RC4_128_SHA"),
                    Map.entry("EXP-RC2-CBC-MD5", "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
                    Map.entry("EXP-DES-CBC-SHA", "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"),
                    Map.entry("DES-CBC-SHA", "TLS_RSA_WITH_DES_CBC_SHA"),
                    Map.entry("EXP-DH-DSS-DES-CBC-SHA", "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"),
                    Map.entry("DH-DSS-DES-CBC-SHA", "TLS_DH_DSS_WITH_DES_CBC_SHA"),
                    Map.entry("DH-DSS-DES-CBC3-SHA", "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"),
                    Map.entry("EXP-DH-RSA-DES-CBC-SHA", "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"),
                    Map.entry("DH-RSA-DES-CBC-SHA", "TLS_DH_RSA_WITH_DES_CBC_SHA"),
                    Map.entry("DH-RSA-DES-CBC3-SHA", "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"),
                    Map.entry("EXP-DHE-DSS-DES-CBC-SHA", "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"),
                    Map.entry("EXP-EDH-DSS-DES-CBC-SHA", "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"),
                    Map.entry("DHE-DSS-DES-CBC-SHA", "TLS_DHE_DSS_WITH_DES_CBC_SHA"),
                    Map.entry("EDH-DSS-DES-CBC-SHA", "TLS_DHE_DSS_WITH_DES_CBC_SHA"),
                    Map.entry("EXP-DHE-RSA-DES-CBC-SHA", "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
                    Map.entry("EXP-EDH-RSA-DES-CBC-SHA", "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
                    Map.entry("DHE-RSA-DES-CBC-SHA", "TLS_DHE_RSA_WITH_DES_CBC_SHA"),
                    Map.entry("EDH-RSA-DES-CBC-SHA", "TLS_DHE_RSA_WITH_DES_CBC_SHA"),
                    Map.entry("EXP-ADH-RC4-MD5", "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"),
                    Map.entry("ADH-RC4-MD5", "TLS_DH_anon_WITH_RC4_128_MD5"),
                    Map.entry("EXP-ADH-DES-CBC-SHA", "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"),
                    Map.entry("ADH-DES-CBC-SHA", "TLS_DH_anon_WITH_DES_CBC_SHA"),
                    Map.entry("KRB5-DES-CBC-SHA", "TLS_KRB5_WITH_DES_CBC_SHA"),
                    Map.entry("KRB5-DES-CBC3-SHA", "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"),
                    Map.entry("KRB5-RC4-SHA", "TLS_KRB5_WITH_RC4_128_SHA"),
                    Map.entry("KRB5-IDEA-CBC-SHA", "TLS_KRB5_WITH_IDEA_CBC_SHA"),
                    Map.entry("KRB5-DES-CBC-MD5", "TLS_KRB5_WITH_DES_CBC_MD5"),
                    Map.entry("KRB5-DES-CBC3-MD5", "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"),
                    Map.entry("KRB5-RC4-MD5", "TLS_KRB5_WITH_RC4_128_MD5"),
                    Map.entry("KRB5-IDEA-CBC-MD5", "TLS_KRB5_WITH_IDEA_CBC_MD5"),
                    Map.entry("EXP-KRB5-DES-CBC-SHA", "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"),
                    Map.entry("EXP-KRB5-RC2-CBC-SHA", "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"),
                    Map.entry("EXP-KRB5-RC4-SHA", "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"),
                    Map.entry("EXP-KRB5-DES-CBC-MD5", "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"),
                    Map.entry("EXP-KRB5-RC2-CBC-MD5", "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"),
                    Map.entry("EXP-KRB5-RC4-MD5", "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"),
                    Map.entry("DH-DSS-AES128-SHA", "TLS_DH_DSS_WITH_AES_128_CBC_SHA"),
                    Map.entry("DH-RSA-AES128-SHA", "TLS_DH_RSA_WITH_AES_128_CBC_SHA"),
                    Map.entry("DH-DSS-AES256-SHA", "TLS_DH_DSS_WITH_AES_256_CBC_SHA"),
                    Map.entry("DH-RSA-AES256-SHA", "TLS_DH_RSA_WITH_AES_256_CBC_SHA"),
                    Map.entry("DH-DSS-AES128-SHA256", "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"),
                    Map.entry("DH-RSA-AES128-SHA256", "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"),
                    Map.entry("DH-DSS-CAMELLIA128-SHA", "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"),
                    Map.entry("DH-RSA-CAMELLIA128-SHA", "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"),
                    Map.entry("DH-DSS-AES256-SHA256", "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"),
                    Map.entry("DH-RSA-AES256-SHA256", "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"),
                    Map.entry("DH-DSS-CAMELLIA256-SHA", "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"),
                    Map.entry("DH-RSA-CAMELLIA256-SHA", "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"),
                    Map.entry("PSK-RC4-SHA", "TLS_PSK_WITH_RC4_128_SHA"),
                    Map.entry("DHE-PSK-RC4-SHA", "TLS_DHE_PSK_WITH_RC4_128_SHA"),
                    Map.entry("RSA-PSK-RC4-SHA", "TLS_RSA_PSK_WITH_RC4_128_SHA"),
                    Map.entry("DH-DSS-SEED-SHA", "TLS_DH_DSS_WITH_SEED_CBC_SHA"),
                    Map.entry("DH-RSA-SEED-SHA", "TLS_DH_RSA_WITH_SEED_CBC_SHA"),
                    Map.entry("DH-RSA-AES128-GCM-SHA256", "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"),
                    Map.entry("DH-RSA-AES256-GCM-SHA384", "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"),
                    Map.entry("DH-DSS-AES128-GCM-SHA256", "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"),
                    Map.entry("DH-DSS-AES256-GCM-SHA384", "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"),
                    Map.entry(
                            "DH-DSS-CAMELLIA128-SHA256", "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"),
                    Map.entry(
                            "DH-RSA-CAMELLIA128-SHA256", "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
                    Map.entry(
                            "DH-DSS-CAMELLIA256-SHA256", "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"),
                    Map.entry(
                            "DH-RSA-CAMELLIA256-SHA256", "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"),
                    Map.entry("ECDH-ECDSA-NULL-SHA", "TLS_ECDH_ECDSA_WITH_NULL_SHA"),
                    Map.entry("ECDH-ECDSA-RC4-SHA", "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"),
                    Map.entry("ECDH-ECDSA-DES-CBC3-SHA", "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"),
                    Map.entry("ECDH-ECDSA-AES128-SHA", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"),
                    Map.entry("ECDH-ECDSA-AES256-SHA", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"),
                    Map.entry("ECDHE-ECDSA-RC4-SHA", "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),
                    Map.entry("ECDH-RSA-NULL-SHA", "TLS_ECDH_RSA_WITH_NULL_SHA"),
                    Map.entry("ECDH-RSA-RC4-SHA", "TLS_ECDH_RSA_WITH_RC4_128_SHA"),
                    Map.entry("ECDH-RSA-DES-CBC3-SHA", "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"),
                    Map.entry("ECDH-RSA-AES128-SHA", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"),
                    Map.entry("ECDH-RSA-AES256-SHA", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"),
                    Map.entry("ECDHE-RSA-RC4-SHA", "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
                    Map.entry("AECDH-RC4-SHA", "TLS_ECDH_anon_WITH_RC4_128_SHA"),
                    Map.entry("ECDH-ECDSA-AES128-SHA256", "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"),
                    Map.entry("ECDH-ECDSA-AES256-SHA384", "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"),
                    Map.entry("ECDH-RSA-AES128-SHA256", "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"),
                    Map.entry("ECDH-RSA-AES256-SHA384", "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"),
                    Map.entry(
                            "ECDH-ECDSA-AES128-GCM-SHA256",
                            "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"),
                    Map.entry(
                            "ECDH-ECDSA-AES256-GCM-SHA384",
                            "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"),
                    Map.entry("ECDH-RSA-AES128-GCM-SHA256", "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"),
                    Map.entry("ECDH-RSA-AES256-GCM-SHA384", "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"),
                    Map.entry("ECDHE-PSK-RC4-SHA", "TLS_ECDHE_PSK_WITH_RC4_128_SHA"),
                    Map.entry("ARIA128-GCM-SHA256", "TLS_RSA_WITH_ARIA_128_GCM_SHA256"),
                    Map.entry("ARIA256-GCM-SHA384", "TLS_RSA_WITH_ARIA_256_GCM_SHA384"),
                    Map.entry("DHE-RSA-ARIA128-GCM-SHA256", "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"),
                    Map.entry("DHE-RSA-ARIA256-GCM-SHA384", "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"),
                    Map.entry("DH-RSA-ARIA128-GCM-SHA256", "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"),
                    Map.entry("DH-RSA-ARIA256-GCM-SHA384", "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"),
                    Map.entry("DHE-DSS-ARIA128-GCM-SHA256", "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"),
                    Map.entry("DHE-DSS-ARIA256-GCM-SHA384", "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"),
                    Map.entry("DH-DSS-ARIA128-GCM-SHA256", "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"),
                    Map.entry("DH-DSS-ARIA256-GCM-SHA384", "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"),
                    Map.entry("ADH-ARIA128-GCM-SHA256", "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"),
                    Map.entry("ADH-ARIA256-GCM-SHA384", "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"),
                    Map.entry(
                            "ECDHE-ECDSA-ARIA128-GCM-SHA256",
                            "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"),
                    Map.entry(
                            "ECDHE-ECDSA-ARIA256-GCM-SHA384",
                            "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"),
                    Map.entry(
                            "ECDH-ECDSA-ARIA128-GCM-SHA256",
                            "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"),
                    Map.entry(
                            "ECDH-ECDSA-ARIA256-GCM-SHA384",
                            "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"),
                    Map.entry("ECDHE-ARIA128-GCM-SHA256", "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"),
                    Map.entry("ECDHE-ARIA256-GCM-SHA384", "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"),
                    Map.entry("ECDH-ARIA128-GCM-SHA256", "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"),
                    Map.entry("ECDH-ARIA256-GCM-SHA384", "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"),
                    Map.entry("PSK-ARIA128-GCM-SHA256", "TLS_PSK_WITH_ARIA_128_GCM_SHA256"),
                    Map.entry("PSK-ARIA256-GCM-SHA384", "TLS_PSK_WITH_ARIA_256_GCM_SHA384"),
                    Map.entry("DHE-PSK-ARIA128-GCM-SHA256", "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"),
                    Map.entry("DHE-PSK-ARIA256-GCM-SHA384", "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"),
                    Map.entry("RSA-PSK-ARIA128-GCM-SHA256", "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"),
                    Map.entry("RSA-PSK-ARIA256-GCM-SHA384", "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"),
                    Map.entry(
                            "ECDH-ECDSA-CAMELLIA128-SHA256",
                            "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"),
                    Map.entry(
                            "ECDH-ECDSA-CAMELLIA256-SHA384",
                            "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"),
                    Map.entry(
                            "ECDH-RSA-CAMELLIA128-SHA256",
                            "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"),
                    Map.entry(
                            "ECDH-RSA-CAMELLIA256-SHA384",
                            "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"));

    private OpenSslCipherSuiteNames() {
        // private
    }

    /** The IANA name of the cipher suite with the given OpenSSL name, when it is listed here. */
    @Nonnull
    static Optional<String> ianaName(@Nonnull String opensslName) {
        return Optional.ofNullable(IANA_NAMES.get(opensslName));
    }
}
