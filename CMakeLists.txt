# 3.24 is needed for LINK_LIBRARY:WHOLE_ARCHIVE support
cmake_minimum_required(VERSION 3.24)
project(vodozemac-cpp VERSION 1.0.0 LANGUAGES CXX)

set(ECM_MODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH ${ECM_MODULE_DIR})

include(ECMSetupVersion)
ecm_setup_version(PROJECT
        VARIABLE_PREFIX VODOZEMAC
        PACKAGE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/VodozemacCppConfigVersion.cmake"
        SOVERSION 1
)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CMAKECONFIG_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/VodozemacCpp")

configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/VodozemacCppConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/VodozemacCppConfig.cmake"
        INSTALL_DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
)

find_package(Corrosion REQUIRED)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

corrosion_import_crate(
        MANIFEST_PATH Cargo.toml
)

# We create our own shared library instead of having Cargo do it
# To work around https://github.com/dtolnay/cxx/issues/1331
add_library(vodozemac-cpp SHARED)
# We need a dummy file so CMake will have something to link with
target_sources(vodozemac-cpp PRIVATE src/dummy.cpp)
# We need to link to the whole archive, otherwise important symbols are thrown away
target_link_libraries(vodozemac-cpp PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,vodozemac-static>")

if(WIN32)
        target_link_libraries(vodozemac-cpp PRIVATE Bcrypt.lib)
endif()
target_include_directories(vodozemac-cpp INTERFACE "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/VodozemacCpp>")

set_target_properties(vodozemac-cpp PROPERTIES
        VERSION ${VODOZEMAC_VERSION}
        SOVERSION ${VODOZEMAC_SOVERSION}
)

# We need to copy this file manually, as it's a symlink and CMake will erroneously try to install it as such
add_custom_target(copy_header ALL DEPENDS cargo-build_vodozemac BYPRODUCTS ${CMAKE_BINARY_DIR}/vodozemac.h VERBATIM COMMAND
        cp -L ${CMAKE_BINARY_DIR}/cargo/build/${Rust_CARGO_TARGET}/cxxbridge/vodozemac/src/lib.rs.h ${CMAKE_BINARY_DIR}/vodozemac.h
)

install(TARGETS vodozemac-cpp EXPORT VodozemacTargets ${KDE_INSTALL_TARGETS_DEFAULT_ARGS})

install(FILES
        "${CMAKE_BINARY_DIR}/vodozemac.h"
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/VodozemacCpp COMPONENT Devel
)

install(FILES
        "${PROJECT_BINARY_DIR}/VodozemacCppConfig.cmake"
        "${PROJECT_BINARY_DIR}/VodozemacCppConfigVersion.cmake"
        DESTINATION "${CMAKECONFIG_INSTALL_DIR}"
        COMPONENT Devel
)

install(EXPORT VodozemacTargets DESTINATION "${CMAKECONFIG_INSTALL_DIR}" FILE VodozemacTargets.cmake NAMESPACE Vodozemac::)
