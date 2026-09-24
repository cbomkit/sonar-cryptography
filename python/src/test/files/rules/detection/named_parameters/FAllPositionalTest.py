from test.module import Foo

# f("hello", 42, "yes") — all three arguments passed by position.
# a satisfies withMethodParameter("str") at index 0.
# b satisfies withNamedMethodParameter("b", "int") via positional fallback at index 1.
# c satisfies withOptionalNamedMethodParameter("c", "str") via positional fallback at index 2.
# → rule fires; c is captured.
result = Foo.f("hello", 42, "yes")
