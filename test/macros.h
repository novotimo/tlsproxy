#ifndef __TEST_MACROS_H
#define __TEST_MACROS_H

// Used only to wrap functions the most basic way
#define WRAP_FUN(fun, ret, args, argnames) \
    ret __real_##fun args;               \
    ret __wrap_##fun args {              \
        if (has_mock())                  \
            return (ret)mock();          \
        return __real_##fun argnames;    \
    }

#define WRAP_FUN_ERR(fun, ret, args, argnames) \
    ret __real_##fun args;               \
    ret __wrap_##fun args {              \
        if (has_mock()) {                \
            int r = (ret)mock();         \
            if (has_mock())              \
                errno = (int)mock();     \
            return r;                    \
        }                                \
        return __real_##fun argnames;    \
    }

#endif
