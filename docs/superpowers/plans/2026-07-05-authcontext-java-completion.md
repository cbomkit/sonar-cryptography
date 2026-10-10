# Complete the AuthContext Detection Family (Java) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the partial AuthContext detection family in Java — verification-anchored rules for every token kind, exhaustive-reasonable library coverage, plus two new kinds (`API_KEY`, `MTLS`) wired into the behavior inference engine.

**Architecture:** Each new rule is a `DetectionRuleBuilder<Tree>` matching an auth-interface type+method (or constructor), tagged with an `AuthContext(Kind.X)`. The existing pipeline translates the finding to a generic `ContextualEvidence` node; the output layer maps its identifier back to `AuthContext.Kind` via `valueOf(...)` and feeds `BehaviorInferenceEngine`. Only three things change: the engine enum (two kinds), the inference mapping (three edits), and the `java` detection rules (split into per-kind classes). Detection tests resolve auth types from pinned API jars.

**Tech Stack:** Java 17, Maven (multi-module), SonarQube Java analyzer + `CheckVerifier`, JUnit 5, AssertJ. New pinned test jars: Nimbus JOSE+JWT / OIDC SDK, Auth0 java-jwt, Spring Security (oauth2-jwt, oauth2-resource-server, saml2-service-provider, core, web), OpenSAML (xmlsec-api, saml-impl), JAX-RS (jakarta + javax), javax servlet, pac4j-http.

## Global Constraints

- **License header:** every new `.java` file starts with the Apache 2.0 header block used across the repo (copy verbatim from `java/src/main/java/com/ibm/plugin/rules/detection/auth/AuthDetectionRules.java`, lines 1–19).
- **Formatting:** run `mvn spotless:apply` before every commit (Google Java Format, AOSP style).
- **Checkstyle:** no unused imports, `@Override` where applicable, private constructors on utility classes.
- **Bundle name:** all auth rules use `.inBundle(() -> "Auth")`.
- **Value factory string:** each rule's `new ValueActionFactory<>("<KIND>")` uses the exact `AuthContext.Kind` name (`"JWT"`, `"OAUTH"`, `"SAML"`, `"PRINCIPAL"`, `"MTLS"`, `"API_KEY"`).
- **No taxonomy edit:** all emitted behavior ids (`authenticates`, `validatesToken`, `usesIdentity`) already exist in `output/src/main/resources/crypto-behavior-taxonomy.json`. Do not modify that file.
- **Test-file compilation model:** `CheckVerifier` semantically analyzes source without full compilation. A rule matches when the **receiver type** and **method/constructor name** resolve. To minimize pinned-jar transitive needs, test-file usages import/qualify **only the anchor type** and pass `null`/cast arguments — never assign returns to types from other jars.

---

### Task 1: Add `API_KEY` and `MTLS` to `AuthContext.Kind`

**Files:**
- Modify: `engine/src/main/java/com/ibm/engine/model/context/AuthContext.java:26-32`
- Test: `engine/src/test/java/com/ibm/engine/model/context/AuthContextTest.java`

**Interfaces:**
- Produces: `AuthContext.Kind.API_KEY`, `AuthContext.Kind.MTLS` (enum constants consumed by Tasks 2, 8, 9).

- [ ] **Step 1: Write the failing test**

Add to `AuthContextTest`:

```java
    @Test
    void carriesNewKinds() {
        assertThat(new AuthContext(AuthContext.Kind.API_KEY).kind())
                .isEqualTo(AuthContext.Kind.API_KEY);
        assertThat(new AuthContext(AuthContext.Kind.MTLS).kind())
                .isEqualTo(AuthContext.Kind.MTLS);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q -pl engine test -Dtest=AuthContextTest`
Expected: FAIL — compilation error, `API_KEY`/`MTLS` not a member of `AuthContext.Kind`.

- [ ] **Step 3: Add the enum constants**

Edit `AuthContext.java` enum to:

```java
    public enum Kind {
        JWT,
        OAUTH,
        SAML,
        PRINCIPAL,
        API_KEY,
        MTLS,
        NONE,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q -pl engine test -Dtest=AuthContextTest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
mvn -q -pl engine spotless:apply
git add engine/src/main/java/com/ibm/engine/model/context/AuthContext.java \
        engine/src/test/java/com/ibm/engine/model/context/AuthContextTest.java
git commit -m "feat(engine): add API_KEY and MTLS auth context kinds"
```

---

### Task 2: Extend `BehaviorInferenceEngine` mapping

**Files:**
- Modify: `output/src/main/java/com/ibm/output/cyclondx/behavior/BehaviorInferenceEngine.java:51-69`
- Test: `output/src/test/java/com/ibm/output/cyclonedx/behavior/BehaviorInferenceEngineTest.java`

**Interfaces:**
- Consumes: `AuthContext.Kind.{SAML,API_KEY,MTLS}` (Task 1).
- Produces: mapping — auth-primary = `{JWT,OAUTH,SAML,PRINCIPAL,API_KEY,MTLS}` → `AUTHENTICATES`; token-primary = `{JWT,OAUTH,SAML}` → `VALIDATES_TOKEN`; identity = `{PRINCIPAL,MTLS}` → `USES_IDENTITY`.

- [ ] **Step 1: Write the failing tests**

Add to `BehaviorInferenceEngineTest`:

```java
    @Test
    void samlYieldsAuthenticatesAndValidatesToken() {
        final Set<CryptoBehavior> result =
                engine.infer(EnumSet.noneOf(CryptoBehavior.class), Set.of(AuthContext.Kind.SAML));
        assertThat(result)
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.VALIDATES_TOKEN);
    }

    @Test
    void apiKeyAuthenticatesOnly() {
        final Set<CryptoBehavior> result =
                engine.infer(
                        EnumSet.noneOf(CryptoBehavior.class), Set.of(AuthContext.Kind.API_KEY));
        assertThat(result).containsOnly(CryptoBehavior.AUTHENTICATES);
    }

    @Test
    void mtlsYieldsAuthenticatesAndUsesIdentity() {
        final Set<CryptoBehavior> result =
                engine.infer(EnumSet.noneOf(CryptoBehavior.class), Set.of(AuthContext.Kind.MTLS));
        assertThat(result)
                .containsOnly(CryptoBehavior.AUTHENTICATES, CryptoBehavior.USES_IDENTITY);
        assertThat(result).doesNotContain(CryptoBehavior.VALIDATES_TOKEN);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `mvn -q -pl output test -Dtest=BehaviorInferenceEngineTest`
Expected: FAIL — `samlYieldsAuthenticatesAndValidatesToken` fails (SAML currently gives `authenticates` only, no `validatesToken`); `apiKeyAuthenticatesOnly` / `mtlsYieldsAuthenticatesAndUsesIdentity` fail (kinds not in any primary set → empty result).

- [ ] **Step 3: Update the mapping**

Replace the three boolean blocks (`hasAuthPrimary`, `hasTokenPrimary`, `hasPrincipal`) in `BehaviorInferenceEngine.infer` with:

```java
        final boolean hasAuthPrimary =
                authSignals.contains(AuthContext.Kind.JWT)
                        || authSignals.contains(AuthContext.Kind.OAUTH)
                        || authSignals.contains(AuthContext.Kind.SAML)
                        || authSignals.contains(AuthContext.Kind.PRINCIPAL)
                        || authSignals.contains(AuthContext.Kind.API_KEY)
                        || authSignals.contains(AuthContext.Kind.MTLS);
        final boolean hasTokenPrimary =
                authSignals.contains(AuthContext.Kind.JWT)
                        || authSignals.contains(AuthContext.Kind.OAUTH)
                        || authSignals.contains(AuthContext.Kind.SAML);
        final boolean hasIdentity =
                authSignals.contains(AuthContext.Kind.PRINCIPAL)
                        || authSignals.contains(AuthContext.Kind.MTLS);

        if (hasAuthPrimary) {
            result.add(CryptoBehavior.AUTHENTICATES);
        }
        if (hasTokenPrimary) {
            result.add(CryptoBehavior.VALIDATES_TOKEN);
        }
        if (hasIdentity) {
            result.add(CryptoBehavior.USES_IDENTITY);
        }
```

Also update the class Javadoc: replace "gated behind a required auth-interface primary" sentence's kind list is fine as-is; append a note: `SAML validates a signed assertion (a bearer credential) so it also yields validatesToken; MTLS and API_KEY corroborate authenticates, and MTLS adds usesIdentity via the peer principal.`

- [ ] **Step 4: Run tests to verify they pass**

Run: `mvn -q -pl output test -Dtest=BehaviorInferenceEngineTest`
Expected: PASS (all 9 tests — the 6 existing plus 3 new).

- [ ] **Step 5: Commit**

```bash
mvn -q -pl output spotless:apply
git add output/src/main/java/com/ibm/output/cyclondx/behavior/BehaviorInferenceEngine.java \
        output/src/test/java/com/ibm/output/cyclonedx/behavior/BehaviorInferenceEngineTest.java
git commit -m "feat(output): map SAML to validatesToken; add API_KEY and MTLS behaviors"
```

---

### Task 3: Refactor `auth/` into per-kind rule classes (behavior-preserving)

Split the single `AuthInterfaceDetection` into per-kind classes so the family scales. This task **preserves current behavior**: only `JWT` (jjwt `parser`/`parserBuilder`) and `PRINCIPAL` (jakarta servlet) still fire.

**Files:**
- Create: `java/src/main/java/com/ibm/plugin/rules/detection/auth/JwtAuthRules.java`
- Create: `java/src/main/java/com/ibm/plugin/rules/detection/auth/OAuthAuthRules.java`
- Create: `java/src/main/java/com/ibm/plugin/rules/detection/auth/SamlAuthRules.java`
- Create: `java/src/main/java/com/ibm/plugin/rules/detection/auth/PrincipalAuthRules.java`
- Create: `java/src/main/java/com/ibm/plugin/rules/detection/auth/MtlsAuthRules.java`
- Create: `java/src/main/java/com/ibm/plugin/rules/detection/auth/ApiKeyAuthRules.java`
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/auth/AuthDetectionRules.java`
- Delete: `java/src/main/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceDetection.java`
- Test: `java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceDetectionTest.java` (unchanged — the gate)

**Interfaces:**
- Produces: `JwtAuthRules.rules()`, `OAuthAuthRules.rules()`, `SamlAuthRules.rules()`, `PrincipalAuthRules.rules()`, `MtlsAuthRules.rules()`, `ApiKeyAuthRules.rules()` — each `static List<IDetectionRule<Tree>>`. Consumed by `AuthDetectionRules.rules()`.

- [ ] **Step 1: Create `JwtAuthRules` with the current jjwt rule verbatim**

```java
/* <Apache 2.0 header> */
package com.ibm.plugin.rules.detection.auth;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class JwtAuthRules {

    private JwtAuthRules() {
        // nothing
    }

    private static final IDetectionRule<Tree> JWT_PARSER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("io.jsonwebtoken.Jwts")
                    .forMethods("parser", "parserBuilder")
                    .shouldBeDetectedAs(new ValueActionFactory<>("JWT"))
                    .withoutParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.JWT))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(JWT_PARSER);
    }
}
```

- [ ] **Step 2: Create `PrincipalAuthRules` with the current servlet rule verbatim**

```java
/* <Apache 2.0 header> */
package com.ibm.plugin.rules.detection.auth;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class PrincipalAuthRules {

    private PrincipalAuthRules() {
        // nothing
    }

    private static final IDetectionRule<Tree> SERVLET_PRINCIPAL =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("jakarta.servlet.http.HttpServletRequest")
                    .forMethods("getUserPrincipal")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PRINCIPAL"))
                    .withoutParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.PRINCIPAL))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(SERVLET_PRINCIPAL);
    }
}
```

- [ ] **Step 3: Create the four empty kind classes**

Create `OAuthAuthRules`, `SamlAuthRules`, `MtlsAuthRules`, `ApiKeyAuthRules`, each with the header and this body (substitute the class name):

```java
/* <Apache 2.0 header> */
package com.ibm.plugin.rules.detection.auth;

import com.ibm.engine.rule.IDetectionRule;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

public final class OAuthAuthRules {

    private OAuthAuthRules() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of();
    }
}
```

- [ ] **Step 4: Rewire `AuthDetectionRules` and delete `AuthInterfaceDetection`**

Replace `AuthDetectionRules` body (keep header) with:

```java
package com.ibm.plugin.rules.detection.auth;

import com.ibm.engine.rule.IDetectionRule;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

/** Authentication / token interface detection, one rule class per {@code AuthContext.Kind}. */
public final class AuthDetectionRules {

    private AuthDetectionRules() {
        // private
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return Stream.of(
                        JwtAuthRules.rules().stream(),
                        OAuthAuthRules.rules().stream(),
                        SamlAuthRules.rules().stream(),
                        PrincipalAuthRules.rules().stream(),
                        MtlsAuthRules.rules().stream(),
                        ApiKeyAuthRules.rules().stream())
                .flatMap(s -> s)
                .toList();
    }
}
```

Then delete the old file:

```bash
git rm java/src/main/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceDetection.java
```

- [ ] **Step 5: Run the detection test to verify behavior is preserved**

Run: `mvn -q -pl java test -Dtest=AuthInterfaceDetectionTest`
Expected: PASS — `observedKinds` still contains `JWT` and `PRINCIPAL` (the test file and jars are unchanged).

- [ ] **Step 6: Commit**

```bash
mvn -q -pl java spotless:apply
git add java/src/main/java/com/ibm/plugin/rules/detection/auth/
git commit -m "refactor(java): split auth detection into per-kind rule classes"
```

---

### Task 4: JWT — retighten jjwt and add Nimbus + Auth0

**Files:**
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/auth/JwtAuthRules.java`
- Modify: `java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceJars.java`
- Modify: `java/src/test/files/rules/detection/auth/AuthInterfaceTestFile.java`
- Modify: `java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceDetectionTest.java:56`
- Create: `java/src/test/resources/test-jars/nimbus-jose-jwt-9.40.jar`, `java/src/test/resources/test-jars/java-jwt-4.4.0.jar`

**Interfaces:**
- Consumes: `AuthContext.Kind.JWT`.
- Produces: verify-anchored JWT rules; the existing `AuthInterfaceDetectionTest` now also observes JWT via `parseSignedClaims` (not `parser()`).

- [ ] **Step 1: Download the pinned jars**

```bash
for A in com.nimbusds:nimbus-jose-jwt:9.40 com.auth0:java-jwt:4.4.0; do
  mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.6.1:copy \
    -Dartifact=$A:jar \
    -DoutputDirectory=java/src/test/resources/test-jars
done
ls java/src/test/resources/test-jars/ | grep -E 'nimbus-jose-jwt-9.40|java-jwt-4.4.0'
```
Expected: both jar filenames printed.

- [ ] **Step 2: Add jars to `AuthInterfaceJars` and write the failing test usage**

In `AuthInterfaceJars.java`, extend the `List.of(...)`:

```java
    public static List<File> jars =
            List.of(
                    new File("src/test/resources/test-jars/jjwt-api-0.12.6.jar"),
                    new File("src/test/resources/test-jars/jakarta.servlet-api-6.0.0.jar"),
                    new File("src/test/resources/test-jars/nimbus-jose-jwt-9.40.jar"),
                    new File("src/test/resources/test-jars/java-jwt-4.4.0.jar"));
```

In `AuthInterfaceTestFile.java`, replace the `useJwt()` method and add two more (drop the `Jwts` import, add the new ones):

```java
    Jws<Claims> useJjwt(JwtParser parser, String jws) {
        return parser.parseSignedClaims(jws);
    }

    boolean useNimbus(SignedJWT jwt, JWSVerifier verifier) throws Exception {
        return jwt.verify(verifier);
    }

    DecodedJWT useAuth0(JWTVerifier verifier) {
        return verifier.verify((String) null);
    }
```

Add imports at the top of the test file:

```java
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
```

(Remove `import io.jsonwebtoken.Jwts;`.)

- [ ] **Step 3: Run the test to verify it fails**

Run: `mvn -q -pl java test -Dtest=AuthInterfaceDetectionTest`
Expected: FAIL — the old rule matched `Jwts.parser()` which is gone; `parseSignedClaims` / Nimbus `verify` / Auth0 `verify` have no rule yet, so no JWT finding is produced on the new usages (the `.verifyNoIssues()` still holds, but if the suite asserts JWT it may still pass from residual — to make the failure explicit, note: after Step 4's assertion tightening this fails cleanly; if it passes here, that only means no JWT assertion regressed). Proceed to implement.

- [ ] **Step 4: Replace the JWT rules**

In `JwtAuthRules.java`, replace `JWT_PARSER` and `rules()`:

```java
    private static final IDetectionRule<Tree> JJWT_PARSE_SIGNED =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("io.jsonwebtoken.JwtParser")
                    .forMethods("parseSignedClaims", "parseClaimsJws")
                    .shouldBeDetectedAs(new ValueActionFactory<>("JWT"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.JWT))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> NIMBUS_SIGNED_JWT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.nimbusds.jwt.SignedJWT", "com.nimbusds.jose.JWSObject")
                    .forMethods("verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("JWT"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.JWT))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> AUTH0_JWT_VERIFIER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("com.auth0.jwt.interfaces.JWTVerifier")
                    .forMethods("verify")
                    .shouldBeDetectedAs(new ValueActionFactory<>("JWT"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.JWT))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(JJWT_PARSE_SIGNED, NIMBUS_SIGNED_JWT, AUTH0_JWT_VERIFIER);
    }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `mvn -q -pl java test -Dtest=AuthInterfaceDetectionTest`
Expected: PASS — `observedKinds` contains `JWT` and `PRINCIPAL`. (The assertion on line 56 is broadened progressively; JWT still asserted.)

If JWT is **not** observed, the likely cause is unresolved types: confirm the two jars are in `AuthInterfaceJars` and that the receiver types (`JwtParser`, `SignedJWT`, `JWTVerifier`) resolve. `withAnyParameters` matches any overload, so argument shape is not the issue.

- [ ] **Step 6: Commit**

```bash
mvn -q -pl java spotless:apply
git add java/src/main/java/com/ibm/plugin/rules/detection/auth/JwtAuthRules.java \
        java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceJars.java \
        java/src/test/files/rules/detection/auth/AuthInterfaceTestFile.java \
        java/src/test/resources/test-jars/nimbus-jose-jwt-9.40.jar \
        java/src/test/resources/test-jars/java-jwt-4.4.0.jar
git commit -m "feat(java): verify-anchored JWT auth rules (jjwt retighten, Nimbus, Auth0)"
```

---

### Task 5: OAUTH — Spring `JwtDecoder`/`OpaqueTokenIntrospector`, Nimbus OIDC

**Files:**
- Modify: `java/src/main/java/com/ibm/plugin/rules/detection/auth/OAuthAuthRules.java`
- Modify: `AuthInterfaceJars.java`, `AuthInterfaceTestFile.java`, `AuthInterfaceDetectionTest.java:56`
- Create jars: `spring-security-oauth2-jwt-6.3.3.jar`, `spring-security-oauth2-resource-server-6.3.3.jar`, `oauth2-oidc-sdk-11.13.jar`

**Interfaces:**
- Consumes: `AuthContext.Kind.OAUTH`.
- Produces: `OAuthAuthRules.rules()` non-empty; test observes `OAUTH`.

- [ ] **Step 1: Download the pinned jars**

```bash
for A in \
  org.springframework.security:spring-security-oauth2-jwt:6.3.3 \
  org.springframework.security:spring-security-oauth2-resource-server:6.3.3 \
  com.nimbusds:oauth2-oidc-sdk:11.13; do
  mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.6.1:copy \
    -Dartifact=$A:jar -DoutputDirectory=java/src/test/resources/test-jars
done
ls java/src/test/resources/test-jars/ | grep -E 'oauth2-jwt|resource-server|oauth2-oidc-sdk'
```
Expected: three jar filenames printed.

- [ ] **Step 2: Add jars + failing test usage**

Append to `AuthInterfaceJars` list:

```java
                    new File("src/test/resources/test-jars/spring-security-oauth2-jwt-6.3.3.jar"),
                    new File(
                            "src/test/resources/test-jars/spring-security-oauth2-resource-server-6.3.3.jar"),
                    new File("src/test/resources/test-jars/oauth2-oidc-sdk-11.13.jar"),
```

Add imports + methods to `AuthInterfaceTestFile.java`:

```java
import com.nimbusds.jwt.JWT;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
```

```java
    void useJwtDecoder(JwtDecoder decoder) {
        decoder.decode((String) null);
    }

    void useIntrospector(OpaqueTokenIntrospector introspector) {
        introspector.introspect((String) null);
    }

    void useOidcValidator(IDTokenValidator validator) throws Exception {
        validator.validate((JWT) null, (Nonce) null);
    }
```

Broaden the assertion in `AuthInterfaceDetectionTest.java` line 56:

```java
        assertThat(observedKinds)
                .contains(AuthContext.Kind.JWT, AuthContext.Kind.PRINCIPAL, AuthContext.Kind.OAUTH);
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `mvn -q -pl java test -Dtest=AuthInterfaceDetectionTest`
Expected: FAIL — `observedKinds` lacks `OAUTH` (no OAuth rule yet).

- [ ] **Step 4: Fill `OAuthAuthRules`**

Replace the class body's `rules()` and imports; the full class:

```java
/* <Apache 2.0 header> */
package com.ibm.plugin.rules.detection.auth;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class OAuthAuthRules {

    private OAuthAuthRules() {
        // nothing
    }

    private static final IDetectionRule<Tree> SPRING_JWT_DECODER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.springframework.security.oauth2.jwt.JwtDecoder",
                            "org.springframework.security.oauth2.jwt.ReactiveJwtDecoder")
                    .forMethods("decode")
                    .shouldBeDetectedAs(new ValueActionFactory<>("OAUTH"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.OAUTH))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SPRING_OPAQUE_INTROSPECTOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector")
                    .forMethods("introspect")
                    .shouldBeDetectedAs(new ValueActionFactory<>("OAUTH"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.OAUTH))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> NIMBUS_ID_TOKEN_VALIDATOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "com.nimbusds.openid.connect.sdk.validators.IDTokenValidator")
                    .forMethods("validate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("OAUTH"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.OAUTH))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(SPRING_JWT_DECODER, SPRING_OPAQUE_INTROSPECTOR, NIMBUS_ID_TOKEN_VALIDATOR);
    }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `mvn -q -pl java test -Dtest=AuthInterfaceDetectionTest`
Expected: PASS — `observedKinds` now includes `OAUTH`.

- [ ] **Step 6: Commit**

```bash
mvn -q -pl java spotless:apply
git add java/src/main/java/com/ibm/plugin/rules/detection/auth/OAuthAuthRules.java \
        java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceJars.java \
        java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceDetectionTest.java \
        java/src/test/files/rules/detection/auth/AuthInterfaceTestFile.java \
        java/src/test/resources/test-jars/spring-security-oauth2-jwt-6.3.3.jar \
        java/src/test/resources/test-jars/spring-security-oauth2-resource-server-6.3.3.jar \
        java/src/test/resources/test-jars/oauth2-oidc-sdk-11.13.jar
git commit -m "feat(java): OAuth auth rules (Spring JwtDecoder/introspect, Nimbus OIDC)"
```

---

### Task 6: SAML — OpenSAML validators + Spring SAML2

**Files:**
- Modify: `SamlAuthRules.java`, `AuthInterfaceJars.java`, `AuthInterfaceTestFile.java`, `AuthInterfaceDetectionTest.java:56`
- Create jars: `opensaml-xmlsec-api-4.3.2.jar`, `opensaml-saml-impl-4.3.2.jar`, `spring-security-saml2-service-provider-6.3.3.jar`

**Interfaces:**
- Consumes: `AuthContext.Kind.SAML`. Produces: `SamlAuthRules.rules()` non-empty; test observes `SAML`.

- [ ] **Step 1: Download the pinned jars**

OpenSAML is hosted on the Shibboleth repo, not Maven Central:

```bash
for A in org.opensaml:opensaml-xmlsec-api:4.3.2 org.opensaml:opensaml-saml-impl:4.3.2; do
  mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.6.1:copy \
    -Dartifact=$A:jar \
    -DremoteRepositories=shibboleth::::https://build.shibboleth.net/maven/releases/ \
    -DoutputDirectory=java/src/test/resources/test-jars
done
mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.6.1:copy \
  -Dartifact=org.springframework.security:spring-security-saml2-service-provider:6.3.3:jar \
  -DoutputDirectory=java/src/test/resources/test-jars
ls java/src/test/resources/test-jars/ | grep -E 'opensaml-xmlsec-api|opensaml-saml-impl|saml2-service-provider'
```
Expected: three jar filenames printed.

- [ ] **Step 2: Add jars + failing test usage**

Append to `AuthInterfaceJars` list:

```java
                    new File("src/test/resources/test-jars/opensaml-xmlsec-api-4.3.2.jar"),
                    new File("src/test/resources/test-jars/opensaml-saml-impl-4.3.2.jar"),
                    new File(
                            "src/test/resources/test-jars/spring-security-saml2-service-provider-6.3.3.jar"),
```

Add imports + methods to `AuthInterfaceTestFile.java`:

```java
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
```

```java
    void useSignatureValidator() throws Exception {
        SignatureValidator.validate(null, null);
    }

    void useProfileValidator(SAMLSignatureProfileValidator validator) throws Exception {
        validator.validate(null);
    }

    void useSpringSaml2(OpenSaml4AuthenticationProvider provider) {
        provider.authenticate(null);
    }
```

Broaden the assertion (line 56) to add `AuthContext.Kind.SAML`.

- [ ] **Step 3: Run the test to verify it fails**

Run: `mvn -q -pl java test -Dtest=AuthInterfaceDetectionTest`
Expected: FAIL — `observedKinds` lacks `SAML`.

- [ ] **Step 4: Fill `SamlAuthRules`**

```java
/* <Apache 2.0 header> */
package com.ibm.plugin.rules.detection.auth;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class SamlAuthRules {

    private SamlAuthRules() {
        // nothing
    }

    private static final IDetectionRule<Tree> OPENSAML_SIGNATURE_VALIDATOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.opensaml.xmlsec.signature.support.SignatureValidator")
                    .forMethods("validate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SAML"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.SAML))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> OPENSAML_PROFILE_VALIDATOR =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.opensaml.saml.security.impl.SAMLSignatureProfileValidator")
                    .forMethods("validate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SAML"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.SAML))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SPRING_SAML2_PROVIDER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider")
                    .forMethods("authenticate")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SAML"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.SAML))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                OPENSAML_SIGNATURE_VALIDATOR, OPENSAML_PROFILE_VALIDATOR, SPRING_SAML2_PROVIDER);
    }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `mvn -q -pl java test -Dtest=AuthInterfaceDetectionTest`
Expected: PASS — `observedKinds` includes `SAML`.

Note: `SignatureValidator.validate` is a **static** call. If the static invocation does not match on `forObjectTypes`, fall back to exercising it as an instance-style match is not possible — instead keep the two instance validators (`SAMLSignatureProfileValidator.validate`, Spring `authenticate`) which are guaranteed to match, and leave the static rule in place (harmless). The test passes as long as SAML is observed from any of the three.

- [ ] **Step 6: Commit**

```bash
mvn -q -pl java spotless:apply
git add java/src/main/java/com/ibm/plugin/rules/detection/auth/SamlAuthRules.java \
        java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceJars.java \
        java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceDetectionTest.java \
        java/src/test/files/rules/detection/auth/AuthInterfaceTestFile.java \
        java/src/test/resources/test-jars/opensaml-xmlsec-api-4.3.2.jar \
        java/src/test/resources/test-jars/opensaml-saml-impl-4.3.2.jar \
        java/src/test/resources/test-jars/spring-security-saml2-service-provider-6.3.3.jar
git commit -m "feat(java): SAML auth rules (OpenSAML validators, Spring SAML2)"
```

---

### Task 7: PRINCIPAL — javax servlet, JAX-RS (both namespaces), Spring `Authentication`

**Files:**
- Modify: `PrincipalAuthRules.java`, `AuthInterfaceJars.java`, `AuthInterfaceTestFile.java`
- Create jars: `javax.servlet-api-4.0.1.jar`, `jakarta.ws.rs-api-3.1.0.jar`, `javax.ws.rs-api-2.1.1.jar`, `spring-security-core-6.3.3.jar`

**Interfaces:**
- Consumes: `AuthContext.Kind.PRINCIPAL`. Produces: broadened `PrincipalAuthRules.rules()`; `PRINCIPAL` still observed (already asserted).

- [ ] **Step 1: Download the pinned jars**

```bash
for A in javax.servlet:javax.servlet-api:4.0.1 jakarta.ws.rs:jakarta.ws.rs-api:3.1.0 \
         javax.ws.rs:javax.ws.rs-api:2.1.1 org.springframework.security:spring-security-core:6.3.3; do
  mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.6.1:copy \
    -Dartifact=$A:jar -DoutputDirectory=java/src/test/resources/test-jars
done
ls java/src/test/resources/test-jars/ | grep -E 'javax.servlet-api|jakarta.ws.rs-api|javax.ws.rs-api|spring-security-core'
```
Expected: four jar filenames printed.

- [ ] **Step 2: Add jars + failing test usage**

Append to `AuthInterfaceJars` list:

```java
                    new File("src/test/resources/test-jars/javax.servlet-api-4.0.1.jar"),
                    new File("src/test/resources/test-jars/jakarta.ws.rs-api-3.1.0.jar"),
                    new File("src/test/resources/test-jars/javax.ws.rs-api-2.1.1.jar"),
                    new File("src/test/resources/test-jars/spring-security-core-6.3.3.jar"),
```

Add to `AuthInterfaceTestFile.java` (import Spring `Authentication` and jakarta JAX-RS `SecurityContext`; reference javax types fully-qualified to avoid simple-name clashes with the jakarta imports):

```java
import jakarta.ws.rs.core.SecurityContext;
import org.springframework.security.core.Authentication;
```

```java
    Principal useJavaxServlet(javax.servlet.http.HttpServletRequest request) {
        return request.getUserPrincipal();
    }

    Principal useJakartaJaxrs(SecurityContext context) {
        return context.getUserPrincipal();
    }

    Principal useJavaxJaxrs(javax.ws.rs.core.SecurityContext context) {
        return context.getUserPrincipal();
    }

    Object useSpringAuthentication(Authentication authentication) {
        return authentication.getPrincipal();
    }
```

(`java.security.Principal` is already imported in the file.)

- [ ] **Step 3: Run the test to verify it fails**

Run: `mvn -q -pl java test -Dtest=AuthInterfaceDetectionTest`
Expected: FAIL — a new AssertJ failure is not expected on `observedKinds` (PRINCIPAL already observed via jakarta servlet), so instead this step guards **coverage of the new receivers**: after adding rules in Step 4, the new usages must match. To make failure explicit, temporarily add to the test's `test()` method:

```java
        assertThat(observedKinds).contains(AuthContext.Kind.PRINCIPAL);
```

is already present. Skip the temporary guard; rely on Step 4 rules matching and Step 5's full-file run. The functional check is: no unresolved-type errors and PRINCIPAL still observed after the new usages compile against the new jars.

- [ ] **Step 4: Broaden `PrincipalAuthRules`**

Replace `SERVLET_PRINCIPAL` and `rules()`:

```java
    private static final IDetectionRule<Tree> SERVLET_PRINCIPAL =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "jakarta.servlet.http.HttpServletRequest",
                            "javax.servlet.http.HttpServletRequest")
                    .forMethods("getUserPrincipal")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PRINCIPAL"))
                    .withoutParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.PRINCIPAL))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> JAXRS_SECURITY_CONTEXT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "jakarta.ws.rs.core.SecurityContext",
                            "javax.ws.rs.core.SecurityContext")
                    .forMethods("getUserPrincipal")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PRINCIPAL"))
                    .withoutParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.PRINCIPAL))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SPRING_AUTHENTICATION =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.springframework.security.core.Authentication")
                    .forMethods("getPrincipal")
                    .shouldBeDetectedAs(new ValueActionFactory<>("PRINCIPAL"))
                    .withoutParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.PRINCIPAL))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(SERVLET_PRINCIPAL, JAXRS_SECURITY_CONTEXT, SPRING_AUTHENTICATION);
    }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `mvn -q -pl java test -Dtest=AuthInterfaceDetectionTest`
Expected: PASS — `observedKinds` contains `PRINCIPAL` (now matched from four receiver types) with no unresolved-type errors.

- [ ] **Step 6: Commit**

```bash
mvn -q -pl java spotless:apply
git add java/src/main/java/com/ibm/plugin/rules/detection/auth/PrincipalAuthRules.java \
        java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceJars.java \
        java/src/test/files/rules/detection/auth/AuthInterfaceTestFile.java \
        java/src/test/resources/test-jars/javax.servlet-api-4.0.1.jar \
        java/src/test/resources/test-jars/jakarta.ws.rs-api-3.1.0.jar \
        java/src/test/resources/test-jars/javax.ws.rs-api-2.1.1.jar \
        java/src/test/resources/test-jars/spring-security-core-6.3.3.jar
git commit -m "feat(java): broaden PRINCIPAL rules (javax servlet, JAX-RS, Spring Authentication)"
```

---

### Task 8: MTLS — X509TrustManager, SSLSession, Spring X509 filter

**Files:**
- Modify: `MtlsAuthRules.java`, `AuthInterfaceJars.java`, `AuthInterfaceTestFile.java`, `AuthInterfaceDetectionTest.java:56`
- Create jar: `spring-security-web-6.3.3.jar`

**Interfaces:**
- Consumes: `AuthContext.Kind.MTLS`. Produces: `MtlsAuthRules.rules()` non-empty; test observes `MTLS`. (`X509TrustManager`/`SSLSession` are JDK `java.base` — no jar.)

- [ ] **Step 1: Download the pinned jar**

```bash
mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.6.1:copy \
  -Dartifact=org.springframework.security:spring-security-web:6.3.3:jar \
  -DoutputDirectory=java/src/test/resources/test-jars
ls java/src/test/resources/test-jars/ | grep spring-security-web
```
Expected: `spring-security-web-6.3.3.jar` printed.

- [ ] **Step 2: Add jar + failing test usage**

Append to `AuthInterfaceJars` list:

```java
                    new File("src/test/resources/test-jars/spring-security-web-6.3.3.jar"),
```

Add imports + methods to `AuthInterfaceTestFile.java`:

```java
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
```

```java
    Principal usePeerPrincipal(SSLSession session) throws Exception {
        return session.getPeerPrincipal();
    }

    void useTrustManager(X509TrustManager manager, java.security.cert.X509Certificate[] chain)
            throws Exception {
        manager.checkClientTrusted(chain, "RSA");
    }

    X509AuthenticationFilter useX509Filter() {
        return new X509AuthenticationFilter();
    }
```

Broaden the assertion (line 56) to add `AuthContext.Kind.MTLS`.

- [ ] **Step 3: Run the test to verify it fails**

Run: `mvn -q -pl java test -Dtest=AuthInterfaceDetectionTest`
Expected: FAIL — `observedKinds` lacks `MTLS`.

- [ ] **Step 4: Fill `MtlsAuthRules`**

```java
/* <Apache 2.0 header> */
package com.ibm.plugin.rules.detection.auth;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class MtlsAuthRules {

    private MtlsAuthRules() {
        // nothing
    }

    private static final IDetectionRule<Tree> X509_TRUST_MANAGER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("javax.net.ssl.X509TrustManager")
                    .forMethods("checkClientTrusted")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MTLS"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.MTLS))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SSL_SESSION_PEER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("javax.net.ssl.SSLSession")
                    .forMethods("getPeerPrincipal", "getPeerCertificates")
                    .shouldBeDetectedAs(new ValueActionFactory<>("MTLS"))
                    .withoutParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.MTLS))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SPRING_X509_FILTER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter")
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>("MTLS"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.MTLS))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(X509_TRUST_MANAGER, SSL_SESSION_PEER, SPRING_X509_FILTER);
    }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `mvn -q -pl java test -Dtest=AuthInterfaceDetectionTest`
Expected: PASS — `observedKinds` includes `MTLS`.

- [ ] **Step 6: Commit**

```bash
mvn -q -pl java spotless:apply
git add java/src/main/java/com/ibm/plugin/rules/detection/auth/MtlsAuthRules.java \
        java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceJars.java \
        java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceDetectionTest.java \
        java/src/test/files/rules/detection/auth/AuthInterfaceTestFile.java \
        java/src/test/resources/test-jars/spring-security-web-6.3.3.jar
git commit -m "feat(java): mTLS auth rules (X509TrustManager, SSLSession, Spring X509 filter)"
```

---

### Task 9: API_KEY — pac4j clients + Spring header pre-auth filter

**Files:**
- Modify: `ApiKeyAuthRules.java`, `AuthInterfaceJars.java`, `AuthInterfaceTestFile.java`, `AuthInterfaceDetectionTest.java:56`
- Create jar: `pac4j-http-5.7.7.jar` (`spring-security-web` already pinned in Task 8)

**Interfaces:**
- Consumes: `AuthContext.Kind.API_KEY`. Produces: `ApiKeyAuthRules.rules()` non-empty; test observes `API_KEY`.

- [ ] **Step 1: Download the pinned jar**

```bash
mvn -q org.apache.maven.plugins:maven-dependency-plugin:3.6.1:copy \
  -Dartifact=org.pac4j:pac4j-http:5.7.7:jar \
  -DoutputDirectory=java/src/test/resources/test-jars
ls java/src/test/resources/test-jars/ | grep pac4j-http
```
Expected: `pac4j-http-5.7.7.jar` printed.

- [ ] **Step 2: Add jar + failing test usage**

Append to `AuthInterfaceJars` list:

```java
                    new File("src/test/resources/test-jars/pac4j-http-5.7.7.jar"),
```

Add imports + methods to `AuthInterfaceTestFile.java`:

```java
import org.pac4j.http.client.direct.HeaderClient;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;
```

```java
    HeaderClient usePac4jHeaderClient() {
        return new HeaderClient();
    }

    RequestHeaderAuthenticationFilter useSpringHeaderFilter() {
        return new RequestHeaderAuthenticationFilter();
    }
```

Broaden the assertion (line 56) to add `AuthContext.Kind.API_KEY`. The final line reads:

```java
        assertThat(observedKinds)
                .contains(
                        AuthContext.Kind.JWT,
                        AuthContext.Kind.PRINCIPAL,
                        AuthContext.Kind.OAUTH,
                        AuthContext.Kind.SAML,
                        AuthContext.Kind.MTLS,
                        AuthContext.Kind.API_KEY);
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `mvn -q -pl java test -Dtest=AuthInterfaceDetectionTest`
Expected: FAIL — `observedKinds` lacks `API_KEY`.

- [ ] **Step 4: Fill `ApiKeyAuthRules`**

```java
/* <Apache 2.0 header> */
package com.ibm.plugin.rules.detection.auth;

import com.ibm.engine.model.context.AuthContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class ApiKeyAuthRules {

    private ApiKeyAuthRules() {
        // nothing
    }

    private static final IDetectionRule<Tree> PAC4J_DIRECT_CLIENT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.pac4j.http.client.direct.HeaderClient",
                            "org.pac4j.http.client.direct.ParameterClient")
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>("API_KEY"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.API_KEY))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SPRING_REQUEST_HEADER_FILTER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter")
                    .forConstructor()
                    .shouldBeDetectedAs(new ValueActionFactory<>("API_KEY"))
                    .withAnyParameters()
                    .buildForContext(new AuthContext(AuthContext.Kind.API_KEY))
                    .inBundle(() -> "Auth")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(PAC4J_DIRECT_CLIENT, SPRING_REQUEST_HEADER_FILTER);
    }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `mvn -q -pl java test -Dtest=AuthInterfaceDetectionTest`
Expected: PASS — `observedKinds` includes all six kinds.

- [ ] **Step 6: Commit**

```bash
mvn -q -pl java spotless:apply
git add java/src/main/java/com/ibm/plugin/rules/detection/auth/ApiKeyAuthRules.java \
        java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceJars.java \
        java/src/test/java/com/ibm/plugin/rules/detection/auth/AuthInterfaceDetectionTest.java \
        java/src/test/files/rules/detection/auth/AuthInterfaceTestFile.java \
        java/src/test/resources/test-jars/pac4j-http-5.7.7.jar
git commit -m "feat(java): API_KEY auth rules (pac4j direct clients, Spring header filter)"
```

---

### Task 10: Full verification across modules

**Files:** none (verification only).

- [ ] **Step 1: Build and test the three touched modules**

Run: `mvn -q -pl engine,output,java test`
Expected: BUILD SUCCESS — includes `AuthContextTest`, `BehaviorInferenceEngineTest` (9 tests), `AuthInterfaceDetectionTest` (all six kinds observed).

- [ ] **Step 2: Verify formatting and style**

Run: `mvn -q spotless:check checkstyle:check -pl engine,output,java`
Expected: no violations. If Spotless reports diffs, run `mvn spotless:apply -pl engine,output,java` and amend the relevant commit.

- [ ] **Step 3: Full package build**

Run: `mvn -q clean package -DskipTests`
Expected: BUILD SUCCESS (plugin JAR assembles with the new classes).

- [ ] **Step 4: Confirm no stray pinned jars are untracked**

Run: `git status --porcelain java/src/test/resources/test-jars/`
Expected: empty output (every downloaded jar was committed with its task).

---

## Self-Review

**Spec coverage:**
- §5.1 JWT (retighten + Nimbus + Auth0) → Task 4. ✓
- §5.2 OAUTH (Spring JwtDecoder/introspect, Nimbus OIDC) → Task 5. ✓
- §5.3 SAML (OpenSAML validators, Spring SAML2) → Task 6. ✓
- §5.4 PRINCIPAL (jakarta/javax servlet, JAX-RS, Spring) → Task 7. ✓
- §5.5 MTLS (X509TrustManager, SSLSession, Spring X509 filter) → Task 8. ✓
- §5.6 API_KEY (pac4j, Spring header filter) → Task 9. ✓
- §3 enum extension (API_KEY, MTLS) → Task 1. ✓
- §6 inference mapping (SAML→validatesToken; MTLS→authenticates+usesIdentity; API_KEY→authenticates) → Task 2. ✓
- File placement (per-kind classes, delete AuthInterfaceDetection) → Task 3. ✓
- §8 testing (detection per kind, inference cases, no taxonomy edit) → Tasks 2, 4–9. ✓
- Non-goals (annotations, cert behaviors, header heuristics) → not implemented, by design. ✓

**Placeholder scan:** No TBD/TODO. Every rule shown in full; `<Apache 2.0 header>` is an explicit copy-from-source instruction (Global Constraints), not a vague placeholder.

**Type consistency:** `AuthContext.Kind` names match verbatim across engine enum, `ValueActionFactory` strings, inference sets, and test assertions (`JWT`, `OAUTH`, `SAML`, `PRINCIPAL`, `MTLS`, `API_KEY`). `rules()` signature `static List<IDetectionRule<Tree>>` is uniform across all six per-kind classes and the aggregator. Inference helper renamed `hasPrincipal`→`hasIdentity` consistently within Task 2.

**Known execution risk (documented, not a placeholder):** Spring/OpenSAML/Nimbus types resolve from single API jars because test-file usages reference only the anchor type and pass `null`/cast arguments (Global Constraints). If a specific rule fails to match on unresolved types, the fix is to confirm the anchor jar is in `AuthInterfaceJars` and that the receiver variable's declared type is the anchor type — `withAnyParameters` removes argument-shape as a variable. The static-call caveat for OpenSAML `SignatureValidator.validate` is called out inline in Task 6, Step 5.
