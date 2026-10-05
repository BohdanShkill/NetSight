if(WIN32)
    find_path(PCAP_INCLUDE_DIR 
        NAMES pcap.h pcap/pcap.h 
        HINTS ${NPCAP_SDK_DIR} $ENV{NPCAP_SDK_DIR} 
        PATHS C:/npcap-sdk "C:/Program Files/Npcap/sdk" 
        PATH_SUFFIXES Include
    )

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(PCAP_LIB_SUFFIX "Lib/x64")
    else()
        set(PCAP_LIB_SUFFIX "Lib/x86")
    endif()

    find_library(PCAP_LIBRARY
        NAMES wpcap
        HINTS ${NPCAP_SDK_DIR} $ENV{NPCAP_SDK_DIR} 
        PATHS C:/npcap-sdk "C:/Program Files/Npcap/sdk" 
        PATH_SUFFIXES ${PCAP_LIB_SUFFIX}
    )

    find_library(PACKET_LIBRARY
        NAMES Packet
        HINTS ${NPCAP_SDK_DIR} $ENV{NPCAP_SDK_DIR} 
        PATHS C:/npcap-sdk "C:/Program Files/Npcap/sdk" 
        PATH_SUFFIXES ${PCAP_LIB_SUFFIX}
    )

    set(PCAP_REQUIRED_VARS PCAP_INCLUDE_DIR PCAP_LIBRARY PACKET_LIBRARY)
    set(PCAP_FAIL_MSG "Npcap SDK not found. Download it from https://npcap.com/#download, unpack (e.g. to C:/npcap-sdk) and pass -DNPCAP_SDK_DIR=<path>")
else()
    find_path(PCAP_INCLUDE_DIR
        NAMES pcap.h pcap/pcap.h
    )

    find_library(PCAP_LIBRARY
        NAMES pcap
    )

    set(PCAP_REQUIRED_VARS PCAP_INCLUDE_DIR PCAP_LIBRARY)
    set(PCAP_FAIL_MSG "libpcap headers not found. Install: sudo apt install libpcap-dev")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
    REQUIRED_VARS ${PCAP_REQUIRED_VARS}
    REASON_FAILURE_MESSAGE "${PCAP_FAIL_MSG}"
)

mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY PACKET_LIBRARY)

if(PCAP_FOUND AND NOT TARGET PCAP::PCAP)
    add_library(PCAP::PCAP UNKNOWN IMPORTED)
    set_target_properties(PCAP::PCAP PROPERTIES 
        IMPORTED_LOCATION "${PCAP_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
    )
    if(WIN32)
        set_target_properties(PCAP::PCAP PROPERTIES
            INTERFACE_LINK_LIBRARIES "${PACKET_LIBRARY};ws2_32;iphlpapi"
        )
    endif()
endif()