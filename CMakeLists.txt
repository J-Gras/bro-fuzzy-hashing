
cmake_minimum_required(VERSION 2.8)

project(Plugin)

include(BroPlugin)

find_package(LibFuzzy)
find_package(TLSH)

if ( SSDEEP_FOUND AND TLSH_FOUND )
	message(STATUS "Libfuzzy (ssdeep) header prefix  : ${SSDEEP_INCLUDE_DIR}")
	message(STATUS "Libfuzzy (ssdeep) library path   : ${SSDEEP_LIBRARY}")
	message(STATUS "TLSH header prefix               : ${TLSH_INCLUDE_DIR}")
	message(STATUS "TLSH library path                : ${TLSH_LIBRARY}")

	include_directories(${SSDEEP_INCLUDE_DIR})

	bro_plugin_begin(JGras FuzzyHashing)
	bro_plugin_cc(src/Plugin.cc)
	bro_plugin_cc(src/FuzzyHash.cc)
	bro_plugin_cc(src/FuzzyHashVal.cc)
	bro_plugin_bif(src/events.bif)
	bro_plugin_bif(src/functions.bif)
	bro_plugin_dist_files(README CHANGES COPYING VERSION)
	bro_plugin_link_library(${SSDEEP_LIBRARY})
	bro_plugin_link_library(${TLSH_LIBRARY})
	bro_plugin_end()
else ()
	message(FATAL_ERROR "Build failed:")
	if ( NOT SSDEEP_FOUND )
		message(FATAL_ERROR "Libfuzzy (ssdeep) not found.")
	endif ()
	if ( NOT TLSH_FOUND )
		message(FATAL_ERROR "TLSH not found.")
	endif ()
endif ()
