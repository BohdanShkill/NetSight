add_executable(netsight
    main.cpp
)

target_link_libraries(netsight PRIVATE
    netsight_capture
    netsight_warnings
)

target_compile_definitions( netsight PRIVATE
    NETSIGHT_VERSION=\"${PROJECT_VERSION}\"
)