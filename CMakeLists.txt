# 3.24 is needed for LINK_LIBRARY:WHOLE_ARCHIVE support
cmake_minimum_required(VERSION 3.24)

project(vodozemac-cpp)

find_package(Corrosion REQUIRED)

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