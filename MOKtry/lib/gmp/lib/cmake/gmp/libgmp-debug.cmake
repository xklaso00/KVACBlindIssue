#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "GMP::libgmp" for configuration "Debug"
set_property(TARGET GMP::libgmp APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(GMP::libgmp PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${_IMPORT_PREFIX}/lib/libgmpd-13.lib"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/bin/libgmpd-13.dll"
  )

list(APPEND _cmake_import_check_targets GMP::libgmp )
list(APPEND _cmake_import_check_files_for_GMP::libgmp "${_IMPORT_PREFIX}/lib/libgmpd-13.lib" "${_IMPORT_PREFIX}/bin/libgmpd-13.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
