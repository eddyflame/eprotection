cmake_minimum_required(VERSION 3.10)

###################################
# Project EPROTECTION components: #
#   1. EPROTECTION C++ library    #
#   2. APP                        #
###################################

project(eprot VERSION 0.1.0 LANGUAGES CXX C)

# [option] CMAKE_BUILD_TYPE (default: "Release")
# Build in one of the following modes: Release, Debug, MiniSizeRel, or RelWithDebInfo.
# Most generators recognize these and can set the compiler flags accordingly. We set
# the build type here before creating the project to prevent the CMake generator from
# overriding our default of "Release".
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
        STRINGS "Release" "Debug")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

# message(STATUS "The CXX compiler : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
# message(STATUS "The C   compiler : ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")

# enable c++17
set(CMAKE_CXX_STANDARD 17)

# CMake modules
include(CMakeDependentOption)
include(CheckCXXCompilerFlag)
include(CheckCXXSourceRuns)
include(CheckLanguage)

# Extra modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)
# include(APSIMacros)

# Always build position-independent-code
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# In Debug mode, define APSI_DEBUG
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(APSI_DEBUG ON)
    # In Debug mode, enable extra compiler flags.
    include(EnableCXXCompilerFlags)
else()
    set(APSI_DEBUG OFF)
endif()
message(STATUS "APSI debug mode: ${APSI_DEBUG}")

# [option] APSI_USE_CXX17_OPTION_STR (default: ON)
# Use C++17, use C++14 otherwise. An error will be thrown if SEAL_USE_CXX17 is ON but APSI_USE_CXX17 is OFF.
set(APSI_USE_CXX17_OPTION_STR "Use C++17")
option(APSI_USE_CXX17 ${APSI_USE_CXX17_OPTION_STR} ON)
message(STATUS "APSI_USE_CXX17: ${APSI_USE_CXX17}")

# Enable security-related compile options (MSVC only)
set(APSI_SECURE_COMPILE_OPTIONS_OPTION_STR "Enable Control Flow Guard and Spectre mitigations (MSVC only)")
option(APSI_SECURE_COMPILE_OPTIONS ${APSI_SECURE_COMPILE_OPTIONS_OPTION_STR} OFF)
mark_as_advanced(APSI_SECURE_COMPILE_OPTIONS)

# Enable AVX detection
set(APSI_DETECT_AVX_OPTION_STR "Detect the presence of AVX extensions")
option(APSI_DETECT_AVX ${APSI_DETECT_AVX_OPTION_STR} ON)
mark_as_advanced(APSI_DETECT_AVX)

# Enable AVX2 detection
set(APSI_DETECT_AVX2_OPTION_STR "Detect the presence of AVX2 extensions")
option(APSI_DETECT_AVX2 ${APSI_DETECT_AVX2_OPTION_STR} ON)
mark_as_advanced(APSI_DETECT_AVX2)

# Path for output
set(OUTLIB_PATH "lib")

# Required files and directories
include(GNUInstallDirs)


# set c++ flags
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall ${CMAKE_CXX_FLAGS}")

#######################################################
# library

# set library name
set(LIB_NAME ${CMAKE_PROJECT_NAME})

# generate shared object
# add_library(${LIB_NAME} SHARED ${LIB_SRCS})
add_library(${LIB_NAME} STATIC)

# add include
target_include_directories(${LIB_NAME} PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/libepro/>
)

# Configurations for FourQlib: system, arch, SIMD, and assembler
target_compile_options(${LIB_NAME} PUBLIC -DHAVE_CONFIG)
target_compile_options(${LIB_NAME} PUBLIC -DUSE_SECURE_SEED)
target_compile_options(${LIB_NAME} PUBLIC -DUSE_ENDO=true)

# Set system
if(MSVC)
    target_compile_options(${LIB_NAME} PUBLIC -D__WINDOWS__)
elseif (UNIX)
    target_compile_options(${LIB_NAME} PUBLIC -D__LINUX__)
endif()

# Set architecture
include(DetectArch)
if(APSI_FOURQ_ARM64)
    # _ARM64_ needs to be set whether the ARM64 optimizations are used
    # (in UNIX) or the generic implementation is used (Windows)
    target_compile_options(${LIB_NAME} PUBLIC -D_ARM64_)
endif()
if(CMAKE_SYSTEM_PROCESSOR STREQUAL x86)
    target_compile_options(${LIB_NAME} PUBLIC -D_X86_)
endif()

if(APSI_FOURQ_AMD64)
    target_compile_options(${LIB_NAME} PUBLIC -D_AMD64_)
    message(STATUS "FourQlib optimization: arch=AMD64")
elseif (APSI_FOURQ_ARM64 AND UNIX)
    message(STATUS "FourQlib optimization: arch=ARM64")
else()
    target_compile_options(${LIB_NAME} PUBLIC -D_GENERIC_)
    message(STATUS "FourQlib optimization: arch=GENERIC")
endif()

# Set AVX or AVX2 if not generic
if(APSI_FOURQ_AMD64 AND (APSI_DETECT_AVX OR APSI_DETECT_AVX2))
    include(FindAVX)
    check_for_avx(${LIB_NAME})
    if (HAVE_AVX2_EXTENSIONS)
        target_compile_options(${LIB_NAME} PUBLIC -D_AVX2_)
        message(STATUS "FourQlib optimization: simd=AVX2")
    elseif(HAVE_AVX_EXTENSIONS)
        target_compile_options(${LIB_NAME} PUBLIC -D_AVX_)
        message(STATUS "FourQlib optimization: simd=AVX")
    endif()
else()
    message(STATUS "FourQlib optimization: simd=OFF")
endif()

# Use optimized assembly on Linux (non-AVX or AVX2)
set(APSI_FOURQ_USE_ASM OFF)
if(UNIX AND NOT APPLE AND NOT CYGWIN AND NOT MINGW)
    check_language(ASM)
    if(CMAKE_ASM_COMPILER)
        enable_language(ASM)
        target_compile_options(${LIB_NAME} PUBLIC -D_ASM_)
        set(APSI_FOURQ_USE_ASM ON)
        message(STATUS "FourQlib optimization: asm=ON")
    endif()
endif()

# add subdirectories
set(APSI_SOURCE_FILES "")
add_subdirectory(libepro/apsi)

set(SEAL_SOURCE_FILES "")
add_subdirectory(libepro/seal)

set(KUKU_SOURCE_FILES "")
add_subdirectory(libepro/kuku)

# add sources
target_sources(${LIB_NAME} PRIVATE
	${APSI_SOURCE_FILES}
	${SEAL_SOURCE_FILES}
	${KUKU_SOURCE_FILES}
)


#######################################################
# binary

# set binary name
set(BIN_NAME ${CMAKE_PROJECT_NAME}_tool)
# set binary source path
set(BIN_SRC_PATH ${CMAKE_SOURCE_DIR}/src)
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

