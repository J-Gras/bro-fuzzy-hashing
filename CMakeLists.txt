
cmake_minimum_required(VERSION 2.8)

project(Plugin)

include(BroPlugin)

find_package(LibFuzzy)

if ( SSDEEP_FOUND )
	message(STATUS "Libfuzzy header prefix  : ${SSDEEP_INCLUDE_DIR}")
	message(STATUS "Libfuzzy library path   : ${SSDEEP_LIBRARY}")

	include_directories(${SSDEEP_INCLUDE_DIR})

	bro_plugin_begin(JGras SSDeep)
	bro_plugin_cc(src/Plugin.cc)
	bro_plugin_cc(src/SSDeep.cc)
	bro_plugin_bif(src/events.bif)
	bro_plugin_dist_files(README CHANGES COPYING VERSION)
	bro_plugin_link_library(${SSDEEP_LIBRARY})
	bro_plugin_end()
else ()
	message(FATAL_ERROR "Build failed:")
	if ( NOT SSDEEP_FOUND )
		message(FATAL_ERROR "Libfuzzy not found.")
	endif ()
endif ()
