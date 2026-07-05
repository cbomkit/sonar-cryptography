# Complete the AuthContext Detection Family (Java) — Design

**Date:** 2026-07-05
**Status:** Experimental feature — design approved, pending implementation plan
**Builds on:** `2026-07-04-crypto-behavior-context-layer-design.md` (contextual evidence layer),
`2026-07-05-contextual-evidence-node-design.md` (the `ContextualEvidence` IR node)
**Module ownership:** `engine` (two new `AuthContext.Kind` values), `java` (new AST detection rules +
pinned test jars), `output` (inference-engine mapping update)

## 1. Summary

The first iteration of AuthContext detection shipped a working but **partial** Phase 1: the
`AuthContext.Kind` enum declares `{ JWT, OAUTH, SAML, PRINCIPAL, NONE }`, yet only **two rules**
exist — jjwt `Jwts.parser()` / `parserBuilder()` → `JWT`, and jakarta servlet `getUserPrincipal()`
→ `PRINCIPAL`. `OAUTH` and `SAML` are declared enum values with **zero** detection rules, and even
`JWT`/`PRINCIPAL` each cover a single library.

This feature **completes the AuthContext family in Java**: it builds verification-anchored rules for
every declared token kind, broadens each kind to its full reasonable library set, retightens the
existing jjwt rule, and adds two new kinds — `API_KEY` and `MTLS`. The downstream mechanism
(`ContextualEvidence` IR node, `BehaviorInferenceEngine`) is unchanged in structure; only its
kind→behavior mapping is extended.

The feature stays **experimental**, consistent with the base and context-layer features: behaviors
are emitted as the namespaced `cbomkit:crypto:behavior` property, and the draft CycloneDX 2.0
taxonomy snapshot remains the source of truth for identifiers.

## 2. Goals / Non-goals

**Goals**
- Give every declared token kind (`JWT`, `OAUTH`, `SAML`) real detection rules anchored on the call
  that actually **verifies** a signature/token — not on construction.
- Broaden each kind to its full reasonable library coverage (exhaustive-reasonable, not top-1).
- Retighten the existing jjwt `JWT` rule from parser *construction* to the verifying parse call.
- Add two new kinds: `API_KEY` (framework-filter anchored) and `MTLS` (client-cert / peer-principal
  anchored), and wire both into the inference engine.
- Keep the change additive: no new engine context class, no new IR node, no new translator.

**Non-goals (documented, deferred)**
- **Annotation-based auth signals** (`@PreAuthorize`, `@RolesAllowed`, `@AuthenticationPrincipal`,
  JAX-RS `@RolesAllowed`). The engine visitor matches only `METHOD_INVOCATION / NEW_CLASS / ENUM`, so
  annotations are structurally unreachable by the current rule mechanism.
- **Certificate / PKI behaviors** (`presentsClientCertificate`, `validatesCertificate`,
  `checksRevocation`). `MTLS` corroborates `authenticates` only; the certificate family stays
  deferred as its own future evidence family.
- **API-key header-extraction heuristics** (`getHeader("X-API-Key")` + string compare). Rejected as
  noisy: header reads are generic and would produce false `authenticates` signals. `API_KEY` anchors
  on framework filters only.
- **New Go / Python coverage** — a separate effort; the shared mechanism already supports them once
  per-language rules + a context translator are added.

## 3. Design decisions (locked)

| Decision | Choice |
|---|---|
| Enum growth | **Extend** `AuthContext.Kind` with `API_KEY`, `MTLS`. Reuse `ContextualEvidence` + `BehaviorInferenceEngine` (no new context, node, or translator). |
| Detection anchor | **Mixed by kind.** Verify-call anchor for `JWT` / `OAUTH` / `SAML` (a real signature/token check exists); identity-access anchor for `PRINCIPAL` and `MTLS` (peer principal access); framework-filter anchor for `API_KEY`. |
| jjwt rule | **Retighten** from `Jwts.parser()` / `parserBuilder()` (construction) to `JwtParser.parseSignedClaims` / `parseClaimsJws` (verification). |
| Library breadth | **Exhaustive-reasonable** per kind, including less-common but real libraries. |
| SAML → behaviors | **SAML joins the token-primary set** → yields `authenticates` **and** `validatesToken` (a verified signed assertion is a validated bearer credential). |
| mTLS → behaviors | **Corroborate `authenticates` only**, plus `usesIdentity` via the authenticated peer principal. No certificate behaviors. |
| API_KEY → behaviors | **`authenticates` only** (conservative). Not `validatesToken` (static shared secret, not a bearer token) and not `usesIdentity`. |
| API_KEY rules | **Framework filters only** — high precision, low recall. Intentionally small, documented to grow. |
| Test resolution | **Pinned API jars** per library in `src/test/resources/test-jars/`, mirroring the existing `AuthInterfaceJars` / `BouncyCastleJars` convention. |

## 4. Architecture

No data-flow change from the context-layer design. Each new rule produces a `Finding` carrying an
`AuthContext(Kind.X)`; the finding translates to a generic `ContextualEvidence` node
(`identifier = kind.name()`) via the existing `JavaAuthContextTranslator`, rides the normal pipeline
inert, and is read scan-wide at emission. The only touched components:

- `engine` — two new `AuthContext.Kind` values.
- `java` — new `DetectionRuleBuilder<Tree>` rules in `rules/detection/auth/`, wired through the
  existing `AuthInterfaceDetection.rules()` → `AuthDetectionRules` → `JavaDetectionRules` chain;
  pinned test jars added to `AuthInterfaceJars`.
- `output` — `BehaviorInferenceEngine` kind-set membership extended (§6).

All rules use the fluent builder, `.buildForContext(new AuthContext(Kind.X))`, `.inBundle(() ->
"Auth")`, `.withoutDependingDetectionRules()`. Verify-anchor rules whose method takes a
token/assertion argument use `.withAnyParameters()`; no-arg access rules use `.withoutParameters()`.

## 5. Rule matrix

### 5.1 `JWT` — verify anchor → `authenticates` + `validatesToken`

| Library | Object type | Method(s) | Params |
|---|---|---|---|
| jjwt *(retighten existing)* | `io.jsonwebtoken.JwtParser` | `parseSignedClaims`, `parseClaimsJws` | any |
| Nimbus JOSE+JWT | `com.nimbusds.jwt.SignedJWT` / `com.nimbusds.jose.JWSObject` | `verify` | any |
| Auth0 java-jwt | `com.auth0.jwt.interfaces.JWTVerifier` | `verify` | any |

Note: `Jwts.parser()` receiver of `parseSignedClaims` resolves to `JwtParser` via semantic analysis
regardless of the fluent build chain, so no depending-rule chaining is required.

### 5.2 `OAUTH` — verify anchor → `authenticates` + `validatesToken`

| Library | Object type | Method(s) | Params |
|---|---|---|---|
| Spring Security resource server | `org.springframework.security.oauth2.jwt.JwtDecoder` / `ReactiveJwtDecoder` | `decode` | any |
| Spring Security introspection | `org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector` | `introspect` | any |
| Nimbus OIDC SDK | `com.nimbusds.openid.connect.sdk.validators.IDTokenValidator` | `validate` | any |

### 5.3 `SAML` — verify anchor → `authenticates` + `validatesToken`

| Library | Object type | Method(s) | Params |
|---|---|---|---|
| OpenSAML xmlsec | `org.opensaml.xmlsec.signature.support.SignatureValidator` | `validate` | any |
| OpenSAML saml | `org.opensaml.saml.security.impl.SAMLSignatureProfileValidator` | `validate` | any |
| Spring Security SAML2 | `org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider` | `authenticate` | any |

### 5.4 `PRINCIPAL` — access anchor → `usesIdentity` (+ corroborates `authenticates`)

| Library | Object type | Method(s) | Params |
|---|---|---|---|
| jakarta servlet *(existing)* | `jakarta.servlet.http.HttpServletRequest` | `getUserPrincipal` | none |
| javax servlet *(legacy)* | `javax.servlet.http.HttpServletRequest` | `getUserPrincipal` | none |
| JAX-RS (jakarta + javax) | `{jakarta,javax}.ws.rs.core.SecurityContext` | `getUserPrincipal` | none |
| Spring Security | `org.springframework.security.core.Authentication` | `getPrincipal` | none |

### 5.5 `MTLS` *(new kind)* — client-cert / peer-principal anchor → `authenticates` + `usesIdentity`

| Anchor | Object type | Method | Kind of match |
|---|---|---|---|
| Client-cert validation | `javax.net.ssl.X509TrustManager` | `checkClientTrusted` | method invocation |
| Authenticated peer access | `javax.net.ssl.SSLSession` | `getPeerPrincipal`, `getPeerCertificates` | method invocation |
| Spring X.509 auth | `org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter` | *(new-class)* | new class |

### 5.6 `API_KEY` *(new kind)* — framework filters only → `authenticates`

| Anchor | Object type | Kind of match |
|---|---|---|
| pac4j header/param credential client | `org.pac4j.http.client.direct.HeaderClient` / `ParameterClient` | new class |
| Spring pre-authentication | `org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter` | usage / new class |

Intentionally small (high precision, low recall). Documented to grow as concrete API-key libraries
are identified; no header-extraction heuristic is added.

**Totals:** ~16–18 rules across ~9–11 new pinned API jars.

## 6. `BehaviorInferenceEngine` mapping (final)

The engine's kind-set membership is extended (structure unchanged — still a total, side-effect-free
function that gates app-level behaviors behind a required primary):

| Set | Kinds | Emits when present |
|---|---|---|
| auth-primary | `JWT`, `OAUTH`, `SAML`, `PRINCIPAL`, **`API_KEY`**, **`MTLS`** | `authenticates` |
| token-primary | `JWT`, `OAUTH`, **`SAML`** | `validatesToken` |
| identity | `PRINCIPAL`, **`MTLS`** | `usesIdentity` |

Crypto-derived `authenticates` (e.g. from a `Mac`) remains gated: it is emitted only when an
auth-primary is present, exactly as today. All other crypto behaviors pass through unchanged.

## 7. Error handling

- Rules that reference a type absent from the analysis classpath simply never match — no crash.
- `BehaviorInferenceEngine.infer` stays total: unrecognized/insufficient evidence → behavior absent;
  never throws, never guesses.
- Empty inference result → no property, no synthetic component solely for it (unchanged).

## 8. Testing

- **Detection tests** (`TestBase` + `CheckVerifier`, single-file, per the suite convention): extend
  `AuthInterfaceTestFile.java` with a usage of each new library and assert every `Kind` — including
  `API_KEY` and `MTLS` — is observed. Add a pinned API jar per library to `AuthInterfaceJars`.
- **Retighten regression:** assert the jjwt rule fires on `parseSignedClaims` / `parseClaimsJws` and
  no longer on bare `Jwts.parser()`.
- **`BehaviorInferenceEngine` unit cases:** `SAML` → `authenticates` + `validatesToken`; `API_KEY` →
  `authenticates` only (no `validatesToken`, no `usesIdentity`); `MTLS` → `authenticates` +
  `usesIdentity`; a MAC-only scan still suppresses `authenticates`.
- **Enum ↔ JSON sync test** (existing) continues to guard identifiers; all emitted behavior ids
  (`authenticates`, `validatesToken`, `usesIdentity`) already exist in the snapshot — no taxonomy
  change.

## 9. Notes / risks

- **Jar maintenance surface.** Exhaustive-reasonable breadth means ~9–11 pinned API jars (Spring
  Security, OpenSAML, Nimbus, Auth0, pac4j, JAX-RS, legacy `javax` servlet). Each is an API-only jar
  resolved deterministically at test time, independent of the Maven runtime classpath — but the set
  is real maintenance surface and should be reviewed as libraries version.
- **`javax` ↔ `jakarta` split.** Servlet and JAX-RS each need both-namespace rules and both jars.
- **API_KEY recall.** Java lacks a canonical API-key library, so this kind will fire rarely by
  design. That is accepted: precision over recall, with the rule set documented to grow.
- **Single-file detection.** All auth primaries are single method-invocation / new-class matches, not
  cross-file hook-resolved detections, so the per-file hook-release pitfall does not apply. Tests stay
  single-file, consistent with the suite.
- **Experimental property.** The `cbomkit:crypto:behavior` value remains a plain comma-joined list of
  behavior ids; external consumers should treat it as non-standard.
