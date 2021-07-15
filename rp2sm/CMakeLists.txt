cmake_minimum_required(VERSION 3.20)

project(rp2sm LANGUAGES CXX)

include(GenerateExportHeader)

add_library(rp2sm SHARED)

target_sources(rp2sm PRIVATE
	src/VMContext.cpp
	src/FunctionCompiler.cpp
	src/CompilerState.cpp
	src/support.cpp
)

target_include_directories(rp2sm PUBLIC include)

generate_export_header(rp2sm
	INCLUDE_GUARD_NAME RP2SM_RP2SM_EXPORT_H
	EXPORT_FILE_NAME include/rp2sm/rp2sm_export.h
)
target_include_directories(rp2sm PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/include")

set_target_properties(rp2sm PROPERTIES CXX_VISIBILITY_PRESET hidden)

target_compile_features(rp2sm PRIVATE cxx_std_20)

set_target_properties(rp2sm PROPERTIES
	C_EXTENSIONS ON
	CXX_EXTENSIONS ON
)

# use libc++?
#target_compile_options(rp2sm PUBLIC -stdlib=libc++)

# warnings
target_compile_options(rp2sm PRIVATE -Wall -Wextra)
# Clang supressions
target_compile_options(rp2sm PRIVATE $<$<AND:$<COMPILE_LANGUAGE:CXX>,$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>>:-Wno-c99-designator>)

target_link_options(rp2sm PRIVATE "$<$<CONFIG:Release>:LINKER:-s>")
