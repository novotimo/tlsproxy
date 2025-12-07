set(PROJ_SRC "${TLSProxy_SOURCE_DIR}/src")
list(APPEND TEST_INC "${CMOCKA_INCLUDE_DIR}")
list(APPEND TEST_INC "${TLSProxy_SOURCE_DIR}/inc")

list(APPEND TEST_LIBS cmocka::cmocka)
list(APPEND TEST_LIBS proxylib)

list(APPEND TEST_TARGETS test_queue)
list(APPEND TEST_FLAGS   " ")

list(APPEND TEST_TARGETS test_queue_bad_malloc)
list(APPEND TEST_FLAGS   "-Wl,--wrap=_test_malloc -Wl,--wrap=_test_calloc")

list(APPEND TEST_TARGETS test_config)
list(APPEND TEST_FLAGS   " ")

list(APPEND TEST_TARGETS test_event)
list(APPEND TEST_FLAGS   "-Wl,--wrap=handle_accept -Wl,--wrap=handle_proxy -Wl,--wrap=errx")

LIST(LENGTH TEST_TARGETS count)
MATH(EXPR count "${count} - 1")
foreach(i RANGE ${count})
  LIST(GET TEST_TARGETS ${i} test_name)
  LIST(GET TEST_FLAGS ${i}   flags)
  if(flags STREQUAL " ")
    add_cmocka_test(
      ${test_name}
      SOURCES ${test_name}.c
      COMPILE_OPTIONS --coverage
      LINK_LIBRARIES "${TEST_LIBS}" --coverage)
  ELSE()
    add_cmocka_test(
      ${test_name}
      SOURCES ${test_name}.c
      COMPILE_OPTIONS --coverage
      LINK_LIBRARIES "${TEST_LIBS}" "${flags}" --coverage)
  ENDIF()    
  add_cmocka_test_environment(${test_name})
  target_include_directories(${test_name} PUBLIC "${TEST_INC}")
endforeach()
add_custom_target(build_tests DEPENDS ${TEST_TARGETS})

setup_target_for_coverage_lcov(
    NAME test_coverage
    EXECUTABLE ctest
    EXCLUDE app inc
    LCOV_ARGS --ignore-errors unused
    DEPENDENCIES proxylib
)
