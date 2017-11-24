cmake_minimum_required (VERSION 2.6)
project (ZKBooPP)


if ("${CMAKE_BUILD_TYPE}" STREQUAL "")
	message(STATUS " ===> Setting default build type RELEASE")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "setting default build type RELEASE" FORCE)
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# Options: -O0 -g for debug, -O2 for release/measurements
#set(GLOBAL_FLAGS "-Wall -fopenmp -fPIC -Wfatal-errors -std=c++11") 
set(GLOBAL_FLAGS "-Wall -fopenmp -fPIC -std=c++11")

#set(CMAKE_C_FLAGS "-std=c99 ${GLOBAL_FLAGS}")
set(CMAKE_CXX_FLAGS "${GLOBAL_FLAGS}")
message(STATUS "Global flags: ${CMAKE_CXX_FLAGS}")

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0" CACHE STRING "" FORCE)
message(STATUS "DEBUG flags: ${CMAKE_CXX_FLAGS_DEBUG}")

set(CMAKE_CXX_FLAGS_RELEASE "-O2" CACHE STRING "" FORCE)
message(STATUS "RELEASE flags: ${CMAKE_CXX_FLAGS_RELEASE}")

set(LIBS crypto)
set(ZKBOOpp_LIB zkboopp)

include_directories("${PROJECT_SOURCE_DIR}/inc")

add_library(${ZKBOOpp_LIB} SHARED src/MpcVariable.cpp src/mpc_types.cpp src/mpc_core.cpp src/zkbpp_core.cpp src/test_utility.cpp)
target_link_libraries(${ZKBOOpp_LIB} ${LIBS})

function(build_executable_cpp cppfile)  
  add_executable(${cppfile} test/${cppfile}.cpp)
  target_link_libraries(${cppfile} ${LIBS} ${ZKBOOpp_LIB})
endfunction()
function(build_executables_cpp)
  foreach(f ${ARGN})
    build_executable_cpp(${f})
  endforeach()
endfunction()

build_executables_cpp(  
  Matrix_test
  MpcVariable_test
  mpc_core_test
  
  sha256_test
  sha3_test
  xorshift128plus_test
  chacha_test
  trivium_test
)


# Compile legacy C files
#add_executable(MPC_SHA256 MPC_SHA256.c)
#target_link_libraries(MPC_SHA256 ${LIBS})

#add_executable(sha3 sha3.c)
