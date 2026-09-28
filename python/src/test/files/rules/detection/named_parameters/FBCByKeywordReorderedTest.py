from test.module import Foo

# f("hello", c="yes", b=42) — a positional, b and c by keyword but in reversed order.
# a satisfies withMethodParameter("str") at index 0.
# b satisfies withNamedMethodParameter("b", "int") by keyword-name lookup "b" (found at index 2).
# c satisfies withOptionalNamedMethodParameter("c", "str") by keyword-name lookup "c" (found at index 1).
# The engine searches the whole argument list by name, so order does not matter.
# → rule fires; c is captured.
result = Foo.f("hello", c="yes", b=42)
