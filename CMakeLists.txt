cmake_minimum_required (VERSION 2.8)
project (hook_finder)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
	main.cpp
	tinylogger.cpp
	remote_pe_reader.cpp
	hook_scanner.cpp
	hollowing_scanner.cpp
	peloader/pe_hdrs_helper.cpp
	peloader/pe_raw_to_virtual.cpp
	peloader/pe_virtual_to_raw.cpp
	peloader/relocate.cpp
	peloader/util.cpp
)

set (hdrs
	tinylogger.h
	remote_pe_reader.h
	scanner_status.h
	hook_scanner.h
	hollowing_scanner.h
	peloader/pe_hdrs_helper.h
	peloader/pe_raw_to_virtual.h
	peloader/pe_virtual_to_raw.h
	peloader/relocate.h
	peloader/util.h
)

add_executable (hook_finder ${hdrs} ${srcs})
