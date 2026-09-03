from test.module import Foo

# f("hello", b=42) — a positional, b by keyword, c absent.
# a satisfies withMethodParameter("str") at index 0.
# b satisfies withNamedMethodParameter("b", "int") by keyword-name lookup "b".
# c is optional and absent; findArgumentByKeyword("c", 2, ...) returns empty.
# → rule fires; no c child in detection store.
result = Foo.f("hello", b=42)
