cmake_minimum_required (VERSION 2.8)
project (hook_finder)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# modules:
set ( M_PARSER "libpeconv/libpeconv" )

# modules paths:
set (PECONV_DIR "${CMAKE_SOURCE_DIR}/${M_PARSER}" CACHE PATH "PEConv main path")
include_directories ( ${PECONV_DIR}/include )

set (srcs
	main.cpp
	tinylogger.cpp
	hook_scanner.cpp
	hollowing_scanner.cpp
	scanner.cpp
)

set (hdrs
	tinylogger.h
	hook_scanner.h
	hollowing_scanner.h
	scanner.h
)

# libs
add_subdirectory (libpeconv/libpeconv)
set ( PECONV_LIB $<TARGET_FILE:libpeconv> CACHE FILE "PEConvLib library path" )

add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} )
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )

# dependencies
add_dependencies(${PROJECT_NAME} libpeconv)
