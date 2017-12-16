# - Try to find ssdeep library (libfuzzy).
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  SSDEEP_INCLUDE_DIR     Set this variable to the root directory of ssdeep if
#                         the module has problems finding the proper path.
#
# Variables defined by this module:
#
#  SSDEEP_FOUND          System has ssdeep libraries and headers.
#  SSDEEP_LIBRARY        The ssdeep library
#  SSDEEP_INCLUDE_DIR    The location of ssdeep headers

find_library(SSDEEP_LIBRARY
    NAMES libfuzzy.so
    HINTS lib64
)

find_path(SSDEEP_INCLUDE_DIR
    NAMES fuzzy.h
    HINTS include
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SSDeep DEFAULT_MSG
    SSDEEP_LIBRARY
    SSDEEP_INCLUDE_DIR
)

mark_as_advanced(
    SSDEEP_LIBRARY
    SSDEEP_INCLUDE_DIR
)
