#libpcap on Linux or Npcap SDK on Windows 10/11.

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
else()
find_path(PCAP_INCLUDE_DIR
          NAMES pcap.h)
find_library(PCAP_LIBRARY
             NAMES pcap)
endif()
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
                                  DEFAULT_MSG
                                  PCAP_INCLUDE_DIR
                                  PCAP_LIBRARY
                                  )

mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY)

if(PCAP_FOUND AND NOT TARGET PCAP::PCAP)
add_library(PCAP::PCAP UNKNOWN IMPORTED)
set_target_properties(PCAP::PCAP PROPERTIES 
                      IMPORTED_LOCATION "${PCAP_LIBRARY}"
                      INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
                     )
endif()