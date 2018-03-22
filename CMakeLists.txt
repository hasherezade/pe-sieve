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
	scanners/mempage_scanner.cpp
	scanners/scanner.cpp
	scanners/module_data.cpp
	scanners/patch_list.cpp
	scanners/patch_analyzer.cpp
)

set (scanners_hdrs
	scanners/hollowing_scanner.h
	scanners/hook_scanner.h
	scanners/module_scanner.h
	scanners/mempage_scanner.h
	scanners/scanner.h
	scanners/module_scan_report.h
	scanners/scan_report.h
	scanners/module_data.h
	scanners/pe_section.h
	scanners/patch_list.h
	scanners/patch_analyzer.h
)

set (utils_srcs
	utils/process_privilege.cpp
	utils/util.cpp
	utils/path_converter.cpp
	utils/workingset_enum.cpp
)

set (utils_hdrs
	utils/util.h
	utils/path_converter.h
	utils/process_privilege.h
	utils/workingset_enum.h
)


set (srcs
	pe_sieve.cpp
	report_formatter.cpp
	results_dumper.cpp
	${scanners_srcs}
	${utils_srcs}
)

set (hdrs
	pe_sieve.h
	report_formatter.h
	results_dumper.h
	include/pe_sieve_types.h
	${scanners_hdrs}
	${utils_hdrs}
)

SOURCE_GROUP("Source Files\\scanners" FILES ${scanners_srcs} )
SOURCE_GROUP("Header Files\\scanners" FILES ${scanners_hdrs} )

SOURCE_GROUP("Source Files\\utils" FILES ${utils_srcs} )
SOURCE_GROUP("Header Files\\utils" FILES ${utils_hdrs} )

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
