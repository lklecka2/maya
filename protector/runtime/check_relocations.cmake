execute_process(
  COMMAND "${READELF}" -rW "${ELF}"
  RESULT_VARIABLE rc
  OUTPUT_VARIABLE relocations
  ERROR_VARIABLE error_text)
if(NOT rc EQUAL 0)
  message(FATAL_ERROR "Unable to inspect Maya runtime relocations: ${error_text}")
endif()
if(NOT relocations MATCHES "There are no relocations")
  message(FATAL_ERROR "Maya runtime contains unsupported relocations:\n${relocations}")
endif()
file(WRITE "${MANIFEST}" "runtime_relocation_manifest_version=1\nrelocations=none\n")
