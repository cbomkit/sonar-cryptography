# Reduce detection-rule memory footprint (BouncyCastle rule graph)

**Issue:** [#476](https://github.com/cbomkit/sonar-cryptography/issues/476)
**Branch:** `fix/476-rule-graph-memoization` (off `origin/main`)
**Date:** 2026-07-05

## Problem

`JavaInventoryRule` builds the Java detection-rule graph by calling
`JavaDetectionRules.rules()`, which expands into **~521,000 distinct rule
objects** — ~520,891 (99.98%) of them from the BouncyCastle rules. Constructing
this many `DetectionRule`/`MethodDetectionRule` objects (each holding a
`MethodMatcher` with captured lambdas and backing lists) can exhaust the
SonarScanner Engine heap during rule construction:

```
Caused by: java.lang.OutOfMemoryError: Java heap space
    at com.ibm.engine.detection.MethodMatcher.<init>(MethodMatcher.java:91)
    at com.ibm.engine.rule.builder.DetectionRuleBuilderImpl.build(...)
    at ...BcBlockCipherEngine.simpleConstructors(...)
    ...
    at com.ibm.plugin.rules.JavaInventoryRule.<init>(JavaInventoryRule.java:39)
```

A workaround (`-Dsonar.scanner.javaOpts=-Xmx2g`) is already shipped and
documented in `docs/TROUBLESHOOTING.md`.

## Root cause

There is **no memoization** in the rule builders. Every `X.rules()` / `X.all()`
call fully re-materializes its entire dependent subtree as brand-new objects,
and these subtrees are embedded at many call sites and compose multiplicatively
along chains such as:

```
BcDerivationFunction → BcMac → BcBlockCipher.all() → BcBlockCipherEngine
```

High-fan-out embed sites (each rebuilds the whole subtree fresh):

| Node                          | Embed sites | Distinct objects in subtree |
|-------------------------------|------------:|----------------------------:|
| `BcBlockCipherEngine.rules()` |          14 |                       1,093 |
| `BcBlockCipher.all()`         |          26 |                       1,759 |
| `BcMac.rules()`               |           5 |                      16,862 |
| `BcDigests.rules()`           |          47 |                           — |
| `BcDerivationFunction.rules()`|           9 |                      48,495 |
| `BouncyCastleDetectionRules.rules()` | —    |                 **520,891** |

(`BcDigests` is embedded at 47 sites; the largest distinct-object subtrees are
`BcMac` and `BcDerivationFunction`, which sit atop the
`BcBlockCipher`/`BcBlockCipherEngine`/`BcDigests` diamonds.)

The graph is a heavily diamond-shared **DAG**: billions of reachable *paths*
but only ~half a million distinct *objects*. The distinct-object count is what
drives the construction-time heap footprint. JCA + SSL + Auth + SecureRandom
together contribute only ~126 objects — the cost is almost entirely BouncyCastle.

## Approach

Memoize the **no-arg (default-context)** `rules()` / `all()` variants across all
BouncyCastle rule classes so each subtree is built **once** and its immutable
result shared by reference at every embed site. This collapses the diamond-shared
DAG from "rebuilt per path" to "built once per node".

The parameterized `rules(IDetectionContext)` / `all(IDetectionContext)`
overloads are **left unchanged**. They are called with non-null contexts in only
a handful of places (e.g. `BcPSSSigner` and `BcOAEPEncoding` pass a
`DigestContext("MGF1")`; `BcOAEPEncoding`/`BcPKCS1Encoding` pass engine
contexts). These few sites keep building fresh; they do not drive the blow-up
and context-keyed caching is not worth the added key/equality complexity.

Scope is **comprehensive**: apply the same memoization pattern uniformly to every
no-arg `rules()`/`all()` across all `Bc*` rule classes (and the small non-BC
classes, for uniformity). Uniform application avoids leaving un-memoized nodes
that would silently re-inflate a shared subtree.

### Why sharing instances is safe (verified)

- `DetectionRule` and `MethodDetectionRule` are immutable `record`s.
- `IDetectionRule.match()` builds a **fresh** `MatchContext.build(false, this)`
  on every call — no per-traversal state is stored on the rule object.
- All traversal state lives in the `DetectionStore` (keyed by store, not by rule
  identity), so the same rule object reached via two different parents produces
  independent detection state.
- The engine has **no rule-identity visited-set**; traversal follows
  `nextDetectionRules()` against actual source-code expressions, so sharing a
  subtree cannot prune legitimate re-detection.
- `DetectionRuleBuilderImpl.addDependingDetectionRules` /
  `withDependingDetectionRules` **copy** their input list
  (`new LinkedList<>(detectionRules)`), so passing a shared cached list into a
  builder can never let a consumer mutate the cache.
- The graph is a confirmed DAG (naive path traversal terminates with finite path
  counts), so lazy cross-class initialization cannot deadlock or cycle.

## Mechanism

A small thread-safe memoizing helper produces a lazy supplier that builds the
list once and stores an **immutable snapshot**:

```java
// Memoize.java (new)
public final class Memoize {
    public static Supplier<List<IDetectionRule<Tree>>> list(
            Supplier<List<IDetectionRule<Tree>>> builder) {
        // double-checked-locking lazy holder; caches List.copyOf(builder.get())
    }
}
```

Each class exposes its no-arg method through a memoized supplier:

```java
private static final Supplier<List<IDetectionRule<Tree>>> RULES =
        Memoize.list(() -> rules(null));

@Nonnull
public static List<IDetectionRule<Tree>> rules() {
    return RULES.get();
}
```

**Composition rewiring (the important detail).** For the memoized singletons to
actually share subtrees, each no-arg method must call child **no-arg** memoized
methods, not the null-context parameterized path.

- Most already do this. E.g. `BcBlockCipher.simpleConstructors` already calls the
  no-arg `BcBlockCipherEngine.rules()` and `BcBlockCipherInit.rules()`, so
  `rules(null)` naturally composes the memoized children.
- The exception is methods that forward `null` down to a child's *parameterized*
  overload. E.g. today `BcBlockCipher.all(null)` calls
  `BcBlockCipherEngine.rules(null)` — a fresh rebuild that bypasses the memo.
  These no-arg methods are rewired to compose the memoized no-arg children:

  ```java
  @Nonnull
  public static List<IDetectionRule<Tree>> all() {          // memoized
      return concat(rules(), BcBlockCipherEngine.rules());  // both singletons
  }
  ```

Thread-safety: rule construction is effectively single-threaded at plugin init,
but the double-checked lazy holder guards against any race cheaply.

## Verification

### Committed regression test

Add a JUnit test (in the `java` module) that:

1. Walks `JavaDetectionRules.rules()` following **both** child edges:
   - `IDetectionRule.nextDetectionRules()`
   - `Parameter.getDetectionRules()` (for parameter-attached depending rules)
2. Dedups visited rule objects by **identity**
   (`Collections.newSetFromMap(new IdentityHashMap<>())`).
3. Counts distinct `DetectionRule` + `MethodDetectionRule` objects.
4. Asserts the count stays **below a threshold** (target `< 60_000`, comfortably
   under the "each subtree built once" estimate of low-tens-of-thousands and far
   below today's ~521k).

The exact threshold is set after measuring the post-fix count, with headroom for
future rule additions.

### Behavior preservation

All existing rule-detection tests must pass **unchanged** — they are the guard
that memoization did not alter detection behavior.

## Acceptance criteria (from #476)

- [ ] `JavaDetectionRules.rules()` distinct-object count reduced by ~10× or more.
- [ ] Detection behavior unchanged (existing rule tests still pass).
- [ ] A scan of a representative project completes with the default Scanner
      Engine heap (no `-Xmx` bump required).

## Files

- **New:** `Memoize` helper (memoizing supplier for `List<IDetectionRule<Tree>>`).
- **New:** regression test asserting the distinct-object count threshold.
- **Modified:** no-arg `rules()`/`all()` methods across the ~30 `Bc*` rule
  classes (and small non-BC rule classes for uniformity). Builders,
  `simpleConstructors`/`specialConstructors` helpers, and the parameterized
  `(IDetectionContext)` overloads are **unchanged**.
- **Unchanged:** `docs/TROUBLESHOOTING.md` workaround stays as a fallback note.

## Out of scope

- Context-keyed caching for the parameterized `rules(IDetectionContext)`
  overloads.
- Restructuring the rule-graph shape or the `DetectionRuleBuilder` API.
- Any change to detection semantics, translation, or CBOM output.
