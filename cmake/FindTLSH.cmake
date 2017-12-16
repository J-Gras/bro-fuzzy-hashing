# - Try to find TLSH library.
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  TLSH_INCLUDE_DIR     Set this variable to the root directory of TLSH if the
#                       module has problems finding the proper path.
#
# Variables defined by this module:
#
#  TLSH_FOUND          System has TLSH libraries and headers.
#  TLSH_LIBRARY        The TLSH library
#  TLSH_INCLUDE_DIR    The location of TLSH headers

find_library(TLSH_LIBRARY
    NAMES libtlsh.so
    HINTS lib64
)

find_path(TLSH_INCLUDE_DIR
    NAMES tlsh.h
    HINTS include
    PATH_SUFFIXES tlsh
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(TLSH DEFAULT_MSG
	TLSH_LIBRARY
    TLSH_INCLUDE_DIR
)

mark_as_advanced(
	TLSH_LIBRARY
    TLSH_INCLUDE_DIR
)
