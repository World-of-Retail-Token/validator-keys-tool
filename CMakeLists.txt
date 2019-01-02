cmake_minimum_required(VERSION 3.9)
project(validator-keys)
add_subdirectory(extras/rmc-libpp)

add_executable(validator-keys src/ValidatorKeys.cpp src/ValidatorKeysTool.cpp)
target_link_libraries (validator-keys Ripple::xrpl_core)
