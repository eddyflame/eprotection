cmake_minimum_required(VERSION 3.10)
project(eprot)

message(STATUS "The CXX compiler : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "The C   compiler : ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")

# enable c++17
set(CMAKE_CXX_STANDARD 17)

# set c++ flags
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall ${CMAKE_CXX_FLAGS}")

#######################################################
# library

# set library name
set(LIB_NAME lib${CMAKE_PROJECT_NAME})

# add subdirectories
set(APSI_SOURCE_FILES "")
add_subdirectory(apsi)

set(SEAL_SOURCE_FILES "")
add_subdirectory(seal)

set(KUKU_SOURCE_FILES "")
add_subdirectory(kuku)

# generate shared object
# add_library(${LIB_NAME} SHARED ${LIB_SRCS})
add_library(${LIB_NAME} STATIC)

# add sources
target_sources(${LIB_NAME} PRIVATE
	${APSI_SOURCE_FILES}
	${SEAL_SOURCE_FILES}
	${KUKU_SOURCE_FILES}
)

# add include
target_include_directories(${LIB_NAME} PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/>
)

# for installing
# install(TARGETS ${LIB_NAME} LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)

# set(
# 	INSTALL_HEAD_FILES
# 	${LIB_SRC_PATH}/RNG.h
# 	${LIB_SRC_PATH}/SM2.h
# )

# install(FILES ${INSTALL_HEAD_FILES} DESTINATION ${CMAKE_INSTALL_PREFIX}/include/)

# set_target_properties(${LIB_NAME} PROPERTIES VERSION 1.0.0 SOVERSION 1)
# set_target_properties(${LIB_NAME} PROPERTIES PREFIX "")


#######################################################
# binary

# set binary name
set(BIN_NAME ${CMAKE_PROJECT_NAME}_tool)
# set binary source path
set(BIN_SRC_PATH ${CMAKE_SOURCE_DIR})
# set source directory
aux_source_directory(${BIN_SRC_PATH} BIN_SRCS)
# set lib header
include_directories(${LIB_SRC_PATH})
# generate binary
add_executable(${BIN_NAME} ${BIN_SRCS})
# set so for binary
target_link_libraries(${BIN_NAME} PRIVATE
	${LIB_NAME}
	pthread
)

# for installing
#install(TARGETS ${BIN_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)

