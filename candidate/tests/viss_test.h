#pragma once
// VISS — minimal header-only test framework.
//
// Why not gtest/Catch2: this codebase has zero external test dependencies,
// and the tests we need are small (parsers, layout assertions, helpers).
// Pulling in a framework would add hundreds of build targets just to run
// a few hundred assertions. This header provides exactly enough.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace viss_test {

struct TestCase {
    const char* file;
    int         line;
    const char* name;
    void (*fn)();
};

// Single global registry. Defined in test_main.cpp.
std::vector<TestCase>& Registry();

// Per-test failure flag, set by EXPECT_*/ASSERT_*. Cleared by the runner
// between tests.
extern int g_FailCount;
extern int g_AssertCount;

struct TestRegistrar { TestRegistrar(const TestCase& tc) { Registry().push_back(tc); } };

inline void ReportFail(const char* file, int line, const char* expr)
{
    g_FailCount++;
    fprintf(stderr, "  FAIL %s:%d: %s\n", file, line, expr);
}

} // namespace viss_test

// ── Test definition ─────────────────────────────────────────────────────────
#define TEST(suite, name)                                                    \
    static void viss_test_##suite##_##name();                                \
    static ::viss_test::TestRegistrar viss_reg_##suite##_##name{             \
        {__FILE__, __LINE__, #suite "." #name, viss_test_##suite##_##name}}; \
    static void viss_test_##suite##_##name()

// ── Assertion macros ────────────────────────────────────────────────────────
// EXPECT_* records a failure but lets the test continue.
// ASSERT_* records a failure and bails out (test still counted as one).

#define VISS_BUMP_ASSERT() (++::viss_test::g_AssertCount)

#define EXPECT_TRUE(cond) do { VISS_BUMP_ASSERT();                           \
    if (!(cond)) ::viss_test::ReportFail(__FILE__, __LINE__,                 \
                                          "EXPECT_TRUE(" #cond ")");          \
    } while (0)

#define EXPECT_FALSE(cond) do { VISS_BUMP_ASSERT();                          \
    if (cond) ::viss_test::ReportFail(__FILE__, __LINE__,                    \
                                       "EXPECT_FALSE(" #cond ")");            \
    } while (0)

#define EXPECT_EQ(a, b) do { VISS_BUMP_ASSERT();                             \
    auto _va = (a); auto _vb = (b);                                          \
    if (!(_va == _vb)) ::viss_test::ReportFail(__FILE__, __LINE__,           \
                                                "EXPECT_EQ(" #a ", " #b ")"); \
    } while (0)

#define EXPECT_NE(a, b) do { VISS_BUMP_ASSERT();                             \
    auto _va = (a); auto _vb = (b);                                          \
    if (_va == _vb) ::viss_test::ReportFail(__FILE__, __LINE__,              \
                                             "EXPECT_NE(" #a ", " #b ")");    \
    } while (0)

#define EXPECT_GE(a, b) do { VISS_BUMP_ASSERT();                             \
    auto _va = (a); auto _vb = (b);                                          \
    if (!(_va >= _vb)) ::viss_test::ReportFail(__FILE__, __LINE__,           \
                                                "EXPECT_GE(" #a ", " #b ")"); \
    } while (0)

#define EXPECT_GT(a, b) do { VISS_BUMP_ASSERT();                             \
    auto _va = (a); auto _vb = (b);                                          \
    if (!(_va > _vb)) ::viss_test::ReportFail(__FILE__, __LINE__,            \
                                               "EXPECT_GT(" #a ", " #b ")");  \
    } while (0)

#define EXPECT_LE(a, b) do { VISS_BUMP_ASSERT();                             \
    auto _va = (a); auto _vb = (b);                                          \
    if (!(_va <= _vb)) ::viss_test::ReportFail(__FILE__, __LINE__,           \
                                                "EXPECT_LE(" #a ", " #b ")"); \
    } while (0)

#define EXPECT_LT(a, b) do { VISS_BUMP_ASSERT();                             \
    auto _va = (a); auto _vb = (b);                                          \
    if (!(_va < _vb)) ::viss_test::ReportFail(__FILE__, __LINE__,            \
                                               "EXPECT_LT(" #a ", " #b ")");  \
    } while (0)

#define EXPECT_STREQ(a, b) do { VISS_BUMP_ASSERT();                          \
    const char* _sa = (a); const char* _sb = (b);                            \
    if (!_sa || !_sb || strcmp(_sa, _sb) != 0)                               \
        ::viss_test::ReportFail(__FILE__, __LINE__,                          \
                                 "EXPECT_STREQ(" #a ", " #b ")");             \
    } while (0)

#define ASSERT_TRUE(cond) do { VISS_BUMP_ASSERT();                           \
    if (!(cond)) { ::viss_test::ReportFail(__FILE__, __LINE__,               \
                                            "ASSERT_TRUE(" #cond ")");        \
        return; }                                                            \
    } while (0)

#define ASSERT_EQ(a, b) do { VISS_BUMP_ASSERT();                             \
    auto _va = (a); auto _vb = (b);                                          \
    if (!(_va == _vb)) {                                                     \
        ::viss_test::ReportFail(__FILE__, __LINE__,                          \
                                 "ASSERT_EQ(" #a ", " #b ")");                \
        return;                                                              \
    } } while (0)
