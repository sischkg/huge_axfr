cmake_minimum_required(VERSION 2.6)
project(cache-poisoning-tool)

find_package( PkgConfig )

set(CMAKE_VERBOSE_MAKEFILE ON)
set(Boost_ADDITIONAL_VERSIONS "1.53" )
find_package( Threads )
find_package( Boost 1.53 )
find_package( OpenSSL REQUIRED )
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIRS})

add_definitions("-Wall -std=c++11 -g -fPIC")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)
set(CMAKE_EXE_LINKER_FLAGS "-L/usr/local/lib -L/usr/local/lib64 ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_EXE_LINKER_FLAGS}")
add_subdirectory( src )

if(NOT without-test)
  include_directories ("${PROJECT_SOURCE_DIR}/src")
  enable_testing()
  add_subdirectory(tests)
endif()


