cmake_minimum_required(VERSION 3.23)

project(TLSProxy VERSION 0.9.0 LANGUAGES C)

if (UNIT_TESTING)
  add_compile_definitions(UNIT_TESTING)
  add_compile_options(-O0)
else()
  add_compile_options(-O2)
endif()

if (ASAN)
  add_compile_options(-fsanitize=address)
  add_link_options(-fsanitize=address -static-libasan)
endif()

if (PROFILING)
  add_compile_options(-pg)
  add_link_options(-pg)
endif()


# All of the warnings, and count them as errors
add_compile_options(-Wall -Wextra -Wshadow -Wsign-conversion -Wpointer-arith
                    -Wstrict-prototypes -Wwrite-strings -Wno-hardened)
# Security compile options
add_compile_options(-fhardened -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fno-strict-aliasing)

configure_file(
  ${CMAKE_SOURCE_DIR}/inc/version.h.in
  ${CMAKE_SOURCE_DIR}/inc/version.h
  @ONLY
)


find_package(OpenSSL REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CYAML REQUIRED libcyaml)

add_library(proxy STATIC)
target_include_directories(proxy PRIVATE inc)
target_include_directories(proxy SYSTEM PRIVATE external)
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

add_executable(tlsproxy)

target_link_libraries(tlsproxy OpenSSL::SSL OpenSSL::Crypto cyaml proxy)
target_sources(tlsproxy
  PRIVATE
  app/main.c
)
target_include_directories(tlsproxy PRIVATE inc)
target_include_directories(tlsproxy SYSTEM PRIVATE external)
set_property(TARGET tlsproxy PROPERTY C_STANDARD 99)

if (UNIT_TESTING)
  list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmocka)
  include(FetchContent)
  FetchContent_Declare(
    cmocka
    GIT_REPOSITORY https://gitlab.com/cmocka/cmocka.git
    GIT_TAG        cmocka-2.0.0
  )
  FetchContent_MakeAvailable(cmocka)
  
  include(AddCMockaTest)
  add_subdirectory(test)
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
