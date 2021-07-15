cmake_minimum_required(VERSION 3.20)
project(rp2sm_chall LANGUAGES CXX)

# GLOBAL COMPILE SETTINGS
# TODO: should be moved into a utility library somewhere probably
include(CheckPIESupported)
check_pie_supported()

include(CheckCXXCompilerFlag)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
check_cxx_compiler_flag(-fstack-protector-strong has_stack_protector_strong)
if(has_stack_protector_strong)
	add_compile_options(-fstack-protector-strong)
else()
	check_cxx_compiler_flag(-fstack-protector has_stack_protector)
	if(has_stack_protector)
		add_compile_options(-fstack-protector)
	else()
		message(WARNING "Stack protector could not be enabled")
	endif()
endif()
# TODO: use tests
add_link_options(LINKER:--sort-common,--as-needed,-z,relro,-z,now)

# MAIN CODE

add_subdirectory(rp2sm)

add_executable(chall
	chall/main.cpp
)
target_link_libraries(chall rp2sm)

# packing
set(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}")
include(CPack)
install(TARGETS chall rp2sm)
set_target_properties(chall PROPERTIES INSTALL_RPATH "\${ORIGIN}/../lib")
