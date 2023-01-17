cmake_minimum_required (VERSION 3.0)

# replace "project_template" by your own project name:
project ( stat_calculator )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
	../stats.h
	../stats_analyzer.h
	../std_dev_calc.h
)

set (hdrs
	../stats_analyzer.cpp
)

set (rsrc
#put your resources here
)

add_definitions( -DDISPLAY_STATS )
add_executable ( ${PROJECT_NAME} ${hdrs} ${srcs} ${rsrc} main.cpp )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
