cmake_minimum_required (VERSION 2.8)
project (pe-sieve)

option(PESIEVE_AS_DLL "Build PE-sieve as a DLL" OFF)
include_directories (
  include
)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# modules:
set ( M_PARSER "libpeconv/libpeconv" )

# modules paths:
set (PECONV_DIR "${PROJECT_SOURCE_DIR}/${M_PARSER}" CACHE PATH "PEConv main path")
include_directories ( ${PECONV_DIR}/include )

set (scanners_srcs
	scanners/hollowing_scanner.cpp
	scanners/hook_scanner.cpp
	scanners/scanner.cpp
)

set (scanners_hdrs
	scanners/hollowing_scanner.h
	scanners/hook_scanner.h
	scanners/scanner.h
	scanners/scan_report.h
)

set (srcs
	pe_sieve.cpp
	utils/process_privilege.cpp
	utils/util.cpp
	report_formatter.cpp
	results_dumper.cpp
	utils/path_converter.cpp
	module_data.cpp
	${scanners_srcs}
)

set (hdrs
	pe_sieve.h
	utils/process_privilege.h
	utils/util.h
	report_formatter.h
	results_dumper.h
	include/pe_sieve_types.h
	utils/path_converter.h
	module_data.h
	${scanners_hdrs}
)

SOURCE_GROUP("Source Files\\scanners" FILES ${scanners_srcs} )
SOURCE_GROUP("Header Files\\scanners" FILES ${scanners_hdrs} )

# libs
add_subdirectory (libpeconv/libpeconv)
set ( PECONV_LIB $<TARGET_FILE:libpeconv> CACHE FILE "PEConvLib library path" )

# Choose to build the DLL or EXE

if(PESIEVE_AS_DLL)
	set (dll_hdrs
		${hdrs}
		include/pe_sieve_api.h
	)
	add_library ( ${PROJECT_NAME} SHARED ${dll_hdrs} ${srcs} dll_main.cpp main.def)
else()
	add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} main.cpp )
endif()

target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )

# dependencies
add_dependencies(${PROJECT_NAME} libpeconv)
