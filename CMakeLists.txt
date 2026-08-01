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


include(CheckCCompilerFlag)

# Warnings
add_compile_options(-Wall -Wextra -Wshadow -Wsign-conversion -Wpointer-arith
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

# Fortify only where there's optimisation to fold the size checks.
add_compile_options(
    "$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE;-D_FORTIFY_SOURCE=3>")

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
