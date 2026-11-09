add_library(netsight_app STATIC
    Cli.cpp
    Signals.cpp
)

target_include_directories(netsight_app PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(netsight_app PUBLIC
    NETSIGHT_VERSION="${PROJECT_VERSION}"
)

if(WIN32)
    target_compile_definitions(netsight_app PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()

if(MSVC)
    target_link_options(netsight_app PUBLIC "/ignore:4199")
endif()

get_target_property(CLI11_INCLUDES CLI11::CLI11 INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories(netsight_app SYSTEM PRIVATE
    ${CLI11_INCLUDES}
)

target_link_libraries(netsight_app
    PUBLIC
        netsight_capture
    PRIVATE
        CLI11::CLI11
        netsight_warnings
)

add_executable(netsight
    main.cpp
)

target_link_libraries(netsight PRIVATE
    netsight_app
    netsight_warnings
)