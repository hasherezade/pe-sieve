cmake_minimum_required (VERSION 2.8)
project (pe-sieve)

option(PESIEVE_AS_DLL "Build PE-sieve as a DLL" OFF)
include_directories (
  include
)

add_compile_options(
	-fpermissive
)

add_compile_definitions(
	_WIN32_WINNT=1536 # 0x600 aka Windows Vista required
)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# modules:
set ( M_PARSER "libpeconv/libpeconv" )

# modules paths:
set (PECONV_DIR "${PROJECT_SOURCE_DIR}/${M_PARSER}" CACHE PATH "PEConv main path")
include_directories ( ${PECONV_DIR}/include )

set (scanners_srcs
	scanners/mapping_scanner.cpp
	scanners/headers_scanner.cpp
	scanners/code_scanner.cpp
	scanners/workingset_scanner.cpp
	scanners/artefact_scanner.cpp
	scanners/iat_scanner.cpp
	scanners/scanner.cpp
	scanners/module_data.cpp
	scanners/mempage_data.cpp
	scanners/patch_list.cpp
	scanners/patch_analyzer.cpp
	scanners/scan_report.cpp
	scanners/scanned_modules.cpp
	scanners/hook_targets_resolver.cpp
)

set (scanners_hdrs
	scanners/mapping_scanner.h
	scanners/headers_scanner.h
	scanners/code_scanner.h
	scanners/module_scanner.h
	scanners/workingset_scanner.h
	scanners/artefact_scanner.h
	scanners/iat_scanner.h
	scanners/scanner.h
	scanners/module_scan_report.h
	scanners/scan_report.h
	scanners/module_data.h
	scanners/mempage_data.h
	scanners/pe_section.h
	scanners/patch_list.h
	scanners/patch_analyzer.h
	scanners/scanned_modules.h
	scanners/hook_targets_resolver.h
)

set (imprec_hdrs
	postprocessors/imp_rec/imp_reconstructor.h
	postprocessors/imp_rec/iat_block.h
	postprocessors/imp_rec/iat_finder.h
	postprocessors/imp_rec/import_table_finder.h
)

set (postprocessors_hdrs
	postprocessors/report_formatter.h
	postprocessors/results_dumper.h
	postprocessors/dump_report.h
	postprocessors/pe_buffer.h
	postprocessors/pe_reconstructor.h
)

set (imprec_srcs
	postprocessors/imp_rec/imp_reconstructor.cpp
	postprocessors/imp_rec/iat_block.cpp
	postprocessors/imp_rec/iat_finder.cpp
	postprocessors/imp_rec/import_table_finder.cpp
)

set (postprocessors_srcs
	postprocessors/report_formatter.cpp
	postprocessors/results_dumper.cpp
	postprocessors/dump_report.cpp
	postprocessors/pe_buffer.cpp
	postprocessors/pe_reconstructor.cpp
)

set (utils_srcs
	utils/format_util.cpp
	utils/process_util.cpp
	utils/process_privilege.cpp
	utils/process_minidump.cpp
	utils/path_util.cpp
	utils/path_converter.cpp
	utils/workingset_enum.cpp
	utils/modules_enum.cpp
	utils/artefacts_util.cpp
)

set (utils_hdrs
	utils/format_util.h
	utils/path_util.h
	utils/path_converter.h
	utils/process_util.h
	utils/process_privilege.h
	utils/process_minidump.h
	utils/workingset_enum.h
	utils/modules_enum.h
	utils/artefacts_util.h
)

set (params_info_hdrs
	params_info/pe_sieve_params_info.h
)

set (params_info_srcs
	params_info/pe_sieve_params_info.cpp
)

set (srcs
	pe_sieve.cpp
	color_scheme.h
	${params_info_srcs}
	${scanners_srcs}
	${postprocessors_srcs}
	${imprec_srcs}
	${utils_srcs}
)

set (hdrs
	pe_sieve.h
	include/pe_sieve_types.h
	${params_info_hdrs}
	${scanners_hdrs}
	${postprocessors_hdrs}
	${imprec_hdrs}
	${utils_hdrs}
)

set (rsrc
	resources.h
	resources.rc
)

# set filters in Visual Studio project:

SOURCE_GROUP("Source Files\\scanners" FILES ${scanners_srcs} )
SOURCE_GROUP("Header Files\\scanners" FILES ${scanners_hdrs} )

SOURCE_GROUP("Source Files\\utils" FILES ${utils_srcs} )
SOURCE_GROUP("Header Files\\utils" FILES ${utils_hdrs} )

SOURCE_GROUP("Source Files\\params_info" FILES ${params_info_srcs} )
SOURCE_GROUP("Header Files\\params_info" FILES ${params_info_hdrs} )

SOURCE_GROUP("Source Files\\postprocessors" FILES ${postprocessors_srcs} )
SOURCE_GROUP("Header Files\\postprocessors" FILES ${postprocessors_hdrs} )

SOURCE_GROUP("Source Files\\postprocessors\\imp_rec" FILES ${imprec_srcs} )
SOURCE_GROUP("Header Files\\postprocessors\\imp_rec" FILES ${imprec_hdrs} )

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
	set_source_files_properties(main.def PROPERTIES HEADER_FILE_ONLY TRUE)
else()
	add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )
endif()

target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} "psapi.lib" "ntdll.lib" "shlwapi")

# dependencies
add_dependencies(${PROJECT_NAME} libpeconv)

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
