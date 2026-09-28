from test.module import Foo

# f(a="hello", b=42, c="yes") — all three arguments passed by keyword.
# a satisfies withMethodParameter("str"): it is a positional rule parameter; the engine reads
#   arguments.get(0) which is the RegularArgument a="hello" and unwraps its expression "hello"
#   (a str literal) — type check passes.
# b satisfies withNamedMethodParameter("b", "int") by keyword-name lookup "b".
# c satisfies withOptionalNamedMethodParameter("c", "str") by keyword-name lookup "c".
# → rule fires; c is captured.
result = Foo.f(a="hello", b=42, c="yes")
