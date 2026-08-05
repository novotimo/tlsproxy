cmake_minimum_required(VERSION 3.23)

project(TLSProxy VERSION 1.1.0 LANGUAGES C)

if (UNIT_TESTING)
  add_compile_definitions(UNIT_TESTING)
  add_compile_options(-O0)
else()
  add_compile_options(-O2)
endif()

# SANITIZE=address,undefined (or any -fsanitize list). Not -static-libasan:
# the test binaries link cmocka as a shared library, and mixing a static ASAN
# runtime with a shared library that also allocates puts the runtime's
# interceptors in the wrong order. Dynamic was measured working against the
# --wrap based mocks; static was not.
if (SANITIZE)
  add_compile_options(-fsanitize=${SANITIZE} -fno-omit-frame-pointer)
  add_link_options(-fsanitize=${SANITIZE})
endif()

# Kept for compatibility with the previous spelling.
if (ASAN)
  add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address)
endif()

# --coverage on the library under test only; the test binaries themselves are
# not what we are measuring.
if (COVERAGE)
  add_compile_options(--coverage -fprofile-update=atomic)
  add_link_options(--coverage)
endif()

if (PROFILING)
  add_compile_options(-pg)
  add_link_options(-pg)
endif()


include(CheckCCompilerFlag)

# Warnings
add_library(warnings INTERFACE)
target_compile_options(warnings INTERFACE
                       -Wall -Wextra -Wshadow -Wsign-conversion -Wpointer-arith
                       -Wstrict-prototypes -Wwrite-strings
                       -Wimplicit-fallthrough=5 -Werror)

# Hardening
check_c_compiler_flag(-Whardened HAVE_W_HARDENED)
check_c_compiler_flag(-fhardened HAVE_F_HARDENED)

if(HAVE_F_HARDENED)
    add_compile_options(-fhardened)
    if(HAVE_W_HARDENED)
        add_compile_options(-Wno-hardened)
    endif()
else()
    # Spell out what -fhardened would have enabled.
    foreach(flag -fstack-protector-strong -fstack-clash-protection
                 -fcf-protection=full -ftrivial-auto-var-init=zero)
        string(MAKE_C_IDENTIFIER "HAVE${flag}" flag_var)
        check_c_compiler_flag(${flag} ${flag_var})
        if(${flag_var})
            add_compile_options(${flag})
        endif()
    endforeach()
    add_link_options(-Wl,-z,relro,-z,now,-z,noexecstack)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Fortify only where there's optimisation to fold the size checks into.
#
# This used to key on the config name alone, which was wrong in a way that made
# a fresh clone fail at the obvious first command: UNIT_TESTING forces -O0, and
# _FORTIFY_SOURCE at -O0 makes glibc emit a #warning, which -Werror turns into a
# build failure. So `cmake -B build -DUNIT_TESTING=y` with no CMAKE_BUILD_TYPE
# did not build, and CI only stayed green because it passes Debug explicitly.
# Key on the thing that actually matters instead: whether we are optimising.
if (NOT UNIT_TESTING)
  add_compile_options(
      "$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE;-D_FORTIFY_SOURCE=3>")
endif()

add_compile_options(-fno-strict-aliasing)


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
target_link_libraries(proxy PRIVATE warnings)

# proxy is a static archive, so its own dependencies have to be declared here
# rather than left to each consumer to list. Consumers were listing OpenSSL and
# cyaml *before* proxy on their link lines, which only worked because the linker
# was not dropping unused shared libraries. Under -Wl,--as-needed -- the default
# on Ubuntu, which is what CI runs -- nothing needs libssl at the point it is
# scanned, so it is discarded, and libproxy.a(logging.c.o) is then left with
# undefined references to SSL_get_current_cipher and SSL_CIPHER_get_name.
# Declaring the dependency PUBLIC makes CMake emit these after libproxy.a for
# every consumer, which is the order the linker actually needs.
target_link_libraries(proxy PUBLIC OpenSSL::SSL OpenSSL::Crypto cyaml)

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
