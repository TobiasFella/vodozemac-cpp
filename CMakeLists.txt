cmake_minimum_required(VERSION 3.24)

project(Vodozemac-cpp)

find_package(Corrosion REQUIRED)

corrosion_import_crate(
    MANIFEST_PATH Cargo.toml
)

add_custom_target(copy_header ALL DEPENDS cargo-build_vodozemac BYPRODUCTS ${CMAKE_BINARY_DIR}/vodozemac.h VERBATIM COMMAND
    cp -L ${CMAKE_BINARY_DIR}/cargo/build/${Rust_CARGO_TARGET}/cxxbridge/vodozemac/src/lib.rs.h ${CMAKE_BINARY_DIR}/vodozemac.h
)

corrosion_install(TARGETS vodozemac)
install(FILES "${CMAKE_BINARY_DIR}/vodozemac.h" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vodozemac)
