from test.module import Foo

# f(a="hello", b=42, c="yes") — all three arguments passed by keyword.
# a satisfies withNamedMethodParameter("a", "str") by name; a positional-only declaration
# would not match this call.
# b satisfies withNamedMethodParameter("b", "int") by keyword-name lookup "b".
# c satisfies withOptionalNamedMethodParameter("c", "str") by keyword-name lookup "c".
# → an all-named rule fires and captures c.
result = Foo.f(a="hello", b=42, c="yes")
