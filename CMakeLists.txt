cmake_minimum_required(VERSION 3.13)
project("namedhcp"
    DESCRIPTION "use DNS to drive dhcp configuration"
    HOMEPAGE_URL "https://github.com/virtualsquare/namedhcp"
    VERSION 0.1.0
    LANGUAGES C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -D_FORTIFY_SOURCE=2 -O2 -pedantic -Wall -Wextra")

include(GNUInstallDirs)
include(CheckIncludeFile)
include(CheckSymbolExists)

set(LIBS_REQUIRED ioth volatilestream iothdns iothconf stropt vdeplug)
set(HEADERS_REQUIRED stropt.h libvdeplug.h ioth.h iothdns.h iothconf.h volatilestream.h)

foreach(THISLIB IN LISTS LIBS_REQUIRED)
  find_library(LIB${THISLIB}_OK ${THISLIB})
  if(NOT LIB${THISLIB}_OK)
    message(FATAL_ERROR "library lib${THISLIB} not found")
  endif()
endforeach(THISLIB)

foreach(HEADER IN LISTS HEADERS_REQUIRED)
  check_include_file(${HEADER} ${HEADER}_OK)
  if(NOT ${HEADER}_OK)
    message(FATAL_ERROR "header file ${HEADER} not found")
  endif()
endforeach(HEADER)

add_definitions(-D_GNU_SOURCE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# configure_file(config.h.in config.h)

add_executable(namedhcp namedhcp.c utils.c)
target_link_libraries(namedhcp ioth volatilestream iothdns iothconf stropt vdeplug)
install(TARGETS namedhcp
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_executable(namedhcp4 namedhcp4.c utils.c)
target_link_libraries(namedhcp4 ioth volatilestream iothdns iothconf stropt vdeplug)
install(TARGETS namedhcp4
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# add_subdirectory(man)

add_custom_target(uninstall
  "${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")


