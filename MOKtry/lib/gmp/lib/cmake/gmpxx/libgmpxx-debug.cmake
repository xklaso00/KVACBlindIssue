#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "GMP::libgmpxx" for configuration "Debug"
set_property(TARGET GMP::libgmpxx APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(GMP::libgmpxx PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${_IMPORT_PREFIX}/lib/libgmpxxd-9.lib"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/bin/libgmpxxd-9.dll"
  )

list(APPEND _cmake_import_check_targets GMP::libgmpxx )
list(APPEND _cmake_import_check_files_for_GMP::libgmpxx "${_IMPORT_PREFIX}/lib/libgmpxxd-9.lib" "${_IMPORT_PREFIX}/bin/libgmpxxd-9.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
