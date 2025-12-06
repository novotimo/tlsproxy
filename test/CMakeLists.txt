list(APPEND TEST_INC "${CMOCKA_INCLUDE_DIR}")
list(APPEND TEST_INC "${TLSProxy_SOURCE_DIR}/inc")

list(APPEND TEST_LIBS cmocka::cmocka)
list(APPEND TEST_LIBS proxylib)

list(APPEND TEST_TARGETS test_queue)
list(APPEND TEST_FLAGS   " ")

list(APPEND TEST_TARGETS test_queue_bad_malloc)
list(APPEND TEST_FLAGS   "-Wl,--wrap,malloc -Wl,--wrap,calloc")

LIST(LENGTH TEST_TARGETS count)
MATH(EXPR count "${COUNT} - 1")
foreach(i RANGE ${count})
  LIST(GET TEST_TARGETS ${i} test_name)
  LIST(GET TEST_FLAGS ${i}   flags)
  if(flags STREQUAL " ")
    add_cmocka_test(
      ${test_name}
      SOURCES "${test_name}.c"
      COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
      LINK_LIBRARIES "${TEST_LIBS}")
  ELSE()
    add_cmocka_test(
      ${test_name}
      SOURCES "${test_name}.c"
      COMPILE_OPTIONS "${DEFAULT_C_COMPILE_FLAGS}"
      LINK_LIBRARIES "${TEST_LIBS}" "${flags}")
  ENDIF()    
  add_cmocka_test_environment(${test_name})
  target_include_directories(${test_name} PUBLIC "${TEST_INC}")
endforeach()
