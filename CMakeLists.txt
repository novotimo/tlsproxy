cmake_minimum_required(VERSION 3.23)

project(TLSProxy VERSION 0.9.0 LANGUAGES C)

if (UNIT_TESTING)
  list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmocka)
  list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/coverage)

  include(CodeCoverage)
  add_compile_definitions(UNIT_TESTING)
  add_compile_options(-O0)
endif()

if (ASAN)
  add_compile_options(-fsanitize=address)
  add_link_options(-fsanitize=address -static-libasan)
endif()

configure_file(
  ${CMAKE_SOURCE_DIR}/inc/version.h.in
  ${CMAKE_SOURCE_DIR}/inc/version.h
  @ONLY
)


find_package(OpenSSL REQUIRED)

# CYaml
add_library(cyaml SHARED IMPORTED)
set_target_properties(cyaml PROPERTIES
  IMPORTED_LOCATION "/usr/local/lib/libcyaml.so"
  INTERFACE_INCLUDE_DIRECTORIES "/usr/local/include"
)

add_library(proxy)
target_include_directories(proxy PRIVATE inc external)
target_sources(proxy
  PRIVATE
  src/config.c
  src/event.c
  src/listen.c
  src/logging.c
  src/proxy.c
  src/queue.c
  src/timeutils.c
  external/ngx_rbtree.c
)
#set_property(TARGET proxy PROPERTY C_STANDARD 99)

add_executable(tlsproxy)

target_link_libraries(tlsproxy OpenSSL::SSL OpenSSL::Crypto cyaml proxy)
target_sources(tlsproxy
  PRIVATE
  app/main.c
)
target_include_directories(tlsproxy PRIVATE inc external)
set_property(TARGET tlsproxy PROPERTY C_STANDARD 99)

if (UNIT_TESTING)
  # This is actually 2.0.0 but they forgot to version bump
  find_package(cmocka 1.9.0 REQUIRED)
  include(AddCMockaTest)
  add_subdirectory(test)
  append_coverage_compiler_flags()
elseif (BUILD_DOC)
  # Doxygen
  find_package(Doxygen
    OPTIONAL dot
    OPTIONAL_COMPONENTS mscgen dia
  )
  if(DOXYGEN_FOUND)
    set(DOXYGEN_HTML_OUTPUT ${PROJECT_BINARY_DIR}/docs)
    set(DOXYGEN_GENERATE_HTML YES)
    list(APPEND DOXYGEN_EXCLUDE_PATTERNS verstable.h doc)
    set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C YES)
    set(DOXYGEN_EXTRACT_ALL YES)
    doxygen_add_docs(docs
      ${PROJECT_SOURCE_DIR}
      ALL
      COMMENT "Generate Doxygen docs"
    )
  endif(DOXYGEN_FOUND)
endif()

#target_compile_options(tlsproxy
#  PRIVATE
#  "-fsanitize=address")
#target_link_options(tlsproxy
#  PRIVATE
#  "-fsanitize=address")
