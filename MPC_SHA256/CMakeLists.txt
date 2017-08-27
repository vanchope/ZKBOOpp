cmake_minimum_required (VERSION 2.6)
project (ZKBoo_MPC_SHA256)

set(CMAKE_C_FLAGS "-fopenmp -g")
set(LIBS crypto)

function(build_executable cfile)
  add_executable(${cfile} ${cfile}.c)
  target_link_libraries(${cfile} ${LIBS})
endfunction()

function(build_executables)
  foreach(f ${ARGN})
    build_executable(${f})
  endforeach()
endfunction()

build_executables(
  MPC_SHA256
)
