from test.module import Foo

# f("hello", b=42, c="yes") — a positional, b and c by keyword, canonical declaration order.
# a satisfies withMethodParameter("str") at index 0.
# b satisfies withNamedMethodParameter("b", "int") by keyword-name lookup "b".
# c satisfies withOptionalNamedMethodParameter("c", "str") by keyword-name lookup "c".
# → rule fires; c is captured.
result = Foo.f("hello", b=42, c="yes")
