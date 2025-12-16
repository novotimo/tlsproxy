set(PROJ_SRC "${TLSProxy_SOURCE_DIR}/src")
list(APPEND TEST_INC "${CMOCKA_INCLUDE_DIR}")
list(APPEND TEST_INC "${TLSProxy_SOURCE_DIR}/inc")
list(APPEND TEST_INC "${TLSProxy_SOURCE_DIR}/external")

list(APPEND TEST_LIBS OpenSSL::Crypto)
list(APPEND TEST_LIBS OpenSSL::SSL)
list(APPEND TEST_LIBS cmocka::cmocka)
list(APPEND TEST_LIBS proxy)

list(APPEND TEST_TARGETS test_queue)
list(APPEND TEST_FLAGS   "-Wl,--wrap=malloc -Wl,--wrap=calloc")

list(APPEND TEST_TARGETS test_config)
list(APPEND TEST_FLAGS   " ")

list(APPEND TEST_TARGETS test_event)
list(APPEND TEST_FLAGS   "-Wl,--wrap=handle_accept -Wl,--wrap=handle_proxy -Wl,--wrap=errx")

list(APPEND TEST_TARGETS test_proxy)
list(APPEND TEST_FLAGS   "-Wl,--wrap=connect -Wl,--wrap=socket -Wl,--wrap=fcntl -Wl,--wrap=close -Wl,--wrap=malloc -Wl,--wrap=free -Wl,--wrap=epoll_ctl -Wl,--wrap=SSL_free -Wl,--wrap=SSL_shutdown -Wl,--wrap=read -Wl,--wrap=SSL_read -Wl,--wrap=send -Wl,--wrap=SSL_write -Wl,--wrap=SSL_get_error -Wl,--wrap=queue_peek -Wl,--wrap=queue_peek_last -Wl,--wrap=ngx_rbtree_delete -Wl,--wrap=ngx_rbtree_insert")

list(APPEND TEST_TARGETS test_listen)
list(APPEND TEST_FLAGS   "-Wl,--wrap=create_proxy -Wl,--wrap=proxy_close -Wl,--wrap=proxy_add_to_epoll -Wl,--wrap=accept -Wl,--wrap=fcntl -Wl,--wrap=SSL_new -Wl,--wrap=SSL_free -Wl,--wrap=SSL_set_accept_state -Wl,--wrap=SSL_set_fd -Wl,--wrap=errx -Wl,--wrap=err -Wl,--wrap=socket -Wl,--wrap=setsockopt -Wl,--wrap=listen -Wl,--wrap=malloc")

LIST(LENGTH TEST_TARGETS count)
MATH(EXPR count "${count} - 1")
foreach(i RANGE ${count})
  LIST(GET TEST_TARGETS ${i} test_name)
  LIST(GET TEST_FLAGS ${i}   flags)
  if(flags STREQUAL " ")
    add_cmocka_test(
      ${test_name}
      SOURCES ${test_name}.c
      LINK_LIBRARIES "${TEST_LIBS}")
  ELSE()
    add_cmocka_test(
      ${test_name}
      SOURCES ${test_name}.c
      LINK_LIBRARIES "${TEST_LIBS}" "${flags}")
  ENDIF()    
  add_cmocka_test_environment(${test_name})
  target_include_directories(${test_name} PUBLIC "${TEST_INC}")
endforeach()
add_custom_target(build_tests DEPENDS ${TEST_TARGETS})
