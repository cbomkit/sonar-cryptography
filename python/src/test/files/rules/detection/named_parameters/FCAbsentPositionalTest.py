from test.module import Foo

# f("hello", 42) — a and b present positionally, c absent.
# a satisfies withMethodParameter("str") at index 0.
# b satisfies withNamedMethodParameter("b", "int") via positional fallback at index 1.
# c is declared withOptionalNamedMethodParameter so its absence does not suppress the rule.
# findArgumentByKeyword("c", 2, ...) finds no keyword match and no positional arg at index 2.
# → rule fires; no c child in detection store.
result = Foo.f("hello", 42)
