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
package com.ibm.plugin.rules.detection.gocrypto;

import com.ibm.engine.model.context.CertificateContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.sonar.plugins.go.api.Tree;

/**
 * Detection rules for Go's crypto/x509 package.
 *
 * <p>Detects usage of:
 *
 * <ul>
 *   <li>x509.ParseCertificate(der) - parses a single DER-encoded certificate
 *   <li>x509.ParseCertificates(der) - parses a sequence of DER-encoded certificates
 *   <li>x509.CreateCertificate(rand, tmpl, parent, pub, priv) - creates a new certificate
 *   <li>x509.ParseCertificateRequest(der) - parses a DER-encoded CSR
 *   <li>x509.CreateCertificateRequest(rand, tmpl, priv) - creates a new CSR
 *   <li>x509.ParsePKIXPublicKey(der) - parses a DER-encoded PKIX public key
 *   <li>x509.MarshalPKIXPublicKey(pub) - marshals a public key to DER-encoded PKIX format
 *   <li>x509.ParsePKCS1PrivateKey(der) - parses a PKCS#1-encoded private key
 *   <li>x509.MarshalPKCS1PrivateKey(key) - marshals a private key to PKCS#1 DER format
 *   <li>x509.ParsePKCS8PrivateKey(der) - parses an unencrypted PKCS#8 private key
 *   <li>x509.MarshalPKCS8PrivateKey(key) - marshals a private key to PKCS#8 DER format
 *   <li>x509.ParseECPrivateKey(der) - parses an EC private key
 *   <li>x509.MarshalECPrivateKey(key) - marshals an EC private key to DER format
 * </ul>
 */
@SuppressWarnings("java:S1192")
public final class GoCryptoX509 {

    private GoCryptoX509() {
        // private
    }

    // x509.ParseCertificate(der []byte) (*Certificate, error)
    private static final IDetectionRule<Tree> PARSE_CERTIFICATE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/x509")
                    .forMethods("ParseCertificate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X509"))
                    .withMethodParameter("[]byte")
                    .buildForContext(new CertificateContext(Map.of("format", "X.509")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // x509.ParseCertificates(der []byte) ([]*Certificate, error)
    private static final IDetectionRule<Tree> PARSE_CERTIFICATES =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/x509")
                    .forMethods("ParseCertificates")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X509"))
                    .withMethodParameter("[]byte")
                    .buildForContext(new CertificateContext(Map.of("format", "X.509")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // x509.CreateCertificate(rand io.Reader, tmpl *Certificate, parent *Certificate,
    // pub any, priv any) ([]byte, error)
    private static final IDetectionRule<Tree> CREATE_CERTIFICATE =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/x509")
                    .forMethods("CreateCertificate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X509"))
                    .withMethodParameter("io.Reader")
                    .withMethodParameter("*x509.Certificate")
                    .withMethodParameter("*x509.Certificate")
                    .withMethodParameter("any")
                    .withMethodParameter("any")
                    .buildForContext(new CertificateContext(Map.of("format", "X.509")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();


    // x509.ParsePKIXPublicKey(der []byte) (pub any, err error)
    private static final IDetectionRule<Tree> PARSE_PKIX_PUBLIC_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/x509")
                    .forMethods("ParsePKIXPublicKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X509"))
                    .withMethodParameter("[]byte")
                    .buildForContext(new PublicKeyContext(Map.of("kind", "X509")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // x509.MarshalPKIXPublicKey(pub any) ([]byte, error)
    private static final IDetectionRule<Tree> MARSHAL_PKIX_PUBLIC_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/x509")
                    .forMethods("MarshalPKIXPublicKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("X509"))
                    .withMethodParameter("any")
                    .buildForContext(new PublicKeyContext(Map.of("kind", "X509")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // x509.ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error)
    private static final IDetectionRule<Tree> PARSE_PKCS1_PRIVATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/x509")
                    .forMethods("ParsePKCS1PrivateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS1"))
                    .withMethodParameter("[]byte")
                    .buildForContext(new PrivateKeyContext(Map.of("kind", "PKCS1")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // x509.MarshalPKCS1PrivateKey(key *rsa.PrivateKey) ([]byte, error)
    private static final IDetectionRule<Tree> MARSHAL_PKCS1_PRIVATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/x509")
                    .forMethods("MarshalPKCS1PrivateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS1"))
                    .withMethodParameter("*rsa.PrivateKey")
                    .buildForContext(new PrivateKeyContext(Map.of("kind", "PKCS1")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // x509.ParsePKCS8PrivateKey(der []byte) (any, error)
    private static final IDetectionRule<Tree> PARSE_PKCS8_PRIVATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/x509")
                    .forMethods("ParsePKCS8PrivateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS8"))
                    .withMethodParameter("[]byte")
                    .buildForContext(new PrivateKeyContext(Map.of("kind", "PKCS8")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // x509.MarshalPKCS8PrivateKey(key any) ([]byte, error)
    private static final IDetectionRule<Tree> MARSHAL_PKCS8_PRIVATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/x509")
                    .forMethods("MarshalPKCS8PrivateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PKCS8"))
                    .withMethodParameter("any")
                    .buildForContext(new PrivateKeyContext(Map.of("kind", "PKCS8")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // x509.ParseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error)
    private static final IDetectionRule<Tree> PARSE_EC_PRIVATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/x509")
                    .forMethods("ParseECPrivateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withMethodParameter("[]byte")
                    .buildForContext(new PrivateKeyContext(Map.of("kind", "EC")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    // x509.MarshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error)
    private static final IDetectionRule<Tree> MARSHAL_EC_PRIVATE_KEY =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("crypto/x509")
                    .forMethods("MarshalECPrivateKey")
                    .shouldBeDetectedAs(new ValueActionFactory<>("EC"))
                    .withMethodParameter("*ecdsa.PrivateKey")
                    .buildForContext(new PrivateKeyContext(Map.of("kind", "EC")))
                    .inBundle(() -> "GoCrypto")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                PARSE_CERTIFICATE,
                PARSE_CERTIFICATES,
                CREATE_CERTIFICATE,

                PARSE_PKIX_PUBLIC_KEY,
                MARSHAL_PKIX_PUBLIC_KEY,
                PARSE_PKCS1_PRIVATE_KEY,
                MARSHAL_PKCS1_PRIVATE_KEY,
                PARSE_PKCS8_PRIVATE_KEY,
                MARSHAL_PKCS8_PRIVATE_KEY,
                PARSE_EC_PRIVATE_KEY,
                MARSHAL_EC_PRIVATE_KEY);
    }
}
