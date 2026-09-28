from test.module import Foo

# f("hello", 42, c="yes") — a and b positional, c by keyword name.
# a satisfies withMethodParameter("str") at index 0.
# b satisfies withNamedMethodParameter("b", "int") via positional fallback at index 1.
# c satisfies withOptionalNamedMethodParameter("c", "str") by keyword-name lookup "c".
# → rule fires; c is captured.
result = Foo.f("hello", 42, c="yes")
