cmake_minimum_required(VERSION 3.23)

project(TLSProxy)

find_package(OpenSSL REQUIRED)

add_library(cyaml SHARED IMPORTED)
set_target_properties(cyaml PROPERTIES
  IMPORTED_LOCATION "/usr/local/lib/libcyaml.so"
  INTERFACE_INCLUDE_DIRECTORIES "/usr/local/include"
)

find_package(Doxygen
  OPTIONAL dot
  OPTIONAL_COMPONENTS mscgen dia
)
if(DOXYGEN_FOUND)
  set(DOXYGEN_HTML_OUTPUT ${PROJECT_BINARY_DIR}/docs)
  set(DOXYGEN_GENERATE_HTML YES)
  doxygen_add_docs(docs
    ${PROJECT_SOURCE_DIR}
    ALL
    COMMENT "Generate Doxygen docs"
  )
endif(DOXYGEN_FOUND)

add_executable(tlsproxy)

target_link_libraries(tlsproxy OpenSSL::SSL cyaml)
target_sources(tlsproxy
  PRIVATE
  src/main.c
  src/connection.c
  src/queue.c
)

