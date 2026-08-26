// VISS — unit test runner entry point.
//
// Adapted from viss_gui/tests/test_main.cpp, with one addition: a test that
// escapes an exception is reported as a failure rather than terminating the
// process. The vissapp library signals every rejection by throwing, so an
// unimplemented or buggy function would otherwise abort the whole run and
// hide the results of every test after it.

#include "viss_test.h"

#include <exception>

namespace viss_test {
std::vector<TestCase>& Registry()
{
    static std::vector<TestCase> r;
    return r;
}
int g_FailCount   = 0;
int g_AssertCount = 0;
} // namespace viss_test

int main(int argc, char** argv)
{
    using namespace viss_test;

    const char* filter = nullptr;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--filter=", 9) == 0) filter = argv[i] + 9;
        else if (strcmp(argv[i], "--list") == 0) {
            for (const auto& tc : Registry()) printf("%s\n", tc.name);
            return 0;
        }
    }

    int total = 0, passed = 0, failed = 0, total_asserts = 0;
    for (const auto& tc : Registry()) {
        if (filter && !strstr(tc.name, filter)) continue;
        ++total;
        int before_fails = g_FailCount;
        int before_asserts = g_AssertCount;
        printf("[ RUN  ] %s\n", tc.name);
        try {
            tc.fn();
        } catch (const std::exception& e) {
            ReportFail(tc.file, tc.line, e.what());
        } catch (...) {
            ReportFail(tc.file, tc.line, "unknown exception escaped the test");
        }
        int new_fails = g_FailCount - before_fails;
        int new_asserts = g_AssertCount - before_asserts;
        total_asserts += new_asserts;
        if (new_fails == 0) {
            ++passed;
            printf("[  OK  ] %s (%d asserts)\n", tc.name, new_asserts);
        } else {
            ++failed;
            printf("[ FAIL ] %s (%d failures of %d asserts)\n",
                   tc.name, new_fails, new_asserts);
        }
    }

    printf("\n──────────────────────────────────────\n");
    printf("Tests: %d total, %d passed, %d failed (%d assertions)\n",
           total, passed, failed, total_asserts);

    return failed == 0 ? 0 : 1;
}
