# VISS — vissapp unit tests.
#
# One executable, `viss-tests`, registering each TEST() at static-init time.
# Same harness as viss_gui/tests: --filter=<substring> runs a subset, --list
# dumps the registered names.

set(VISSAPP_TEST_SOURCES
    test_main.cpp
    test_public.cpp
    xtra_test_security.cpp
)

# The grading suite is dropped in beside these when a submission is scored.
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test_hidden.cpp)
    list(APPEND VISSAPP_TEST_SOURCES test_hidden.cpp)
endif()

add_executable(viss-tests ${VISSAPP_TEST_SOURCES})
target_link_libraries(viss-tests PRIVATE vissapp_core)
target_compile_options(viss-tests PRIVATE -Wall -Wextra)
target_compile_definitions(viss-tests PRIVATE
    VISSAPP_FIXTURES="${CMAKE_SOURCE_DIR}/fixtures"
    VISSAPP_KEYS="${CMAKE_SOURCE_DIR}/keys"
)

add_test(NAME viss-tests COMMAND viss-tests)
