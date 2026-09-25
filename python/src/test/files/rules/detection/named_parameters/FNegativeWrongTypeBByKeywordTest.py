from test.module import Foo

# b is required and has the wrong type even when supplied by name.
result = Foo.f("hello", b="42")
