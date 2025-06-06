# Add any custom CMake logic here.
# Automated template updates will leave this file untouched.

find_package(SSDeep)
find_package(TLSH)

if ( SSDEEP_FOUND AND TLSH_FOUND )
#if ( TLSH_FOUND )
	message(STATUS "Libfuzzy (ssdeep) header prefix  : ${SSDEEP_INCLUDE_DIR}")
	message(STATUS "Libfuzzy (ssdeep) library path   : ${SSDEEP_LIBRARY}")
	message(STATUS "TLSH header prefix               : ${TLSH_INCLUDE_DIR}")
	message(STATUS "TLSH library path                : ${TLSH_LIBRARY}")

	include_directories(${SSDEEP_INCLUDE_DIR})
	include_directories(${TLSH_INCLUDE_DIR})

	zeek_plugin_link_library(${SSDEEP_LIBRARY})
	zeek_plugin_link_library(${TLSH_LIBRARY})
else ()
	message(FATAL_ERROR "Build failed:")
	if ( NOT SSDEEP_FOUND )
		message(FATAL_ERROR "Libfuzzy (ssdeep) not found.")
	endif ()
	if ( NOT TLSH_FOUND )
		message(FATAL_ERROR "TLSH not found.")
	endif ()
endif ()
