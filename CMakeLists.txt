cmake_minimum_required(VERSION 3.23)

project(TLSProxy)

find_package(OpenSSL REQUIRED)

add_library(cyaml SHARED IMPORTED)
set_target_properties(cyaml PROPERTIES
  IMPORTED_LOCATION "/usr/local/lib/libcyaml.so"
  INTERFACE_INCLUDE_DIRECTORIES "/usr/local/include"
  )

add_executable(tlsproxy)
target_link_libraries(tlsproxy OpenSSL::SSL cyaml)
target_sources(tlsproxy
  PRIVATE
  main.cpp
)

