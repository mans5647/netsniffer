cmake_minimum_required(VERSION 3.5)

project(
  NetSniffer
  VERSION 0.1
  LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
  set(USER_PERSONAL_APPDATA_DIR "$ENV{USERPROFILE}\\AppData\\Local")
elseif(UNIX)

  set(USER_PERSONAL_APPDATA_DIR "/home/")

  execute_process(
    COMMAND "whoami"
    RESULT_VARIABLE USERNAME_RESULT
    OUTPUT_VARIABLE USERNAME
    OUTPUT_STRIP_TRAILING_WHITESPACE)

  if(NOT USERNAME_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to get username")
  endif()

  string(CONCAT USER_PERSONAL_APPDATA_DIR ${USER_PERSONAL_APPDATA_DIR}
                ${USERNAME})

endif()

set(SOURCE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(HEADER_PATH ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(UI_PATH ${SOURCE_PATH}/ui)
set(CMAKE_AUTOUIC_SEARCH_PATHS ${UI_PATH})
set(CMAKE_INSTALL_PREFIX "${USER_PERSONAL_APPDATA_DIR}/netsniffer")
set(ICONS_DIR "${CMAKE_SOURCE_DIR}/icons")
set(HEX_VIEW_DIR ${CMAKE_CURRENT_SOURCE_DIR}/QHexView)
set(INCLUDE_MEMORY_BUF ${HEX_VIEW_DIR}/document/buffer)

set(PROJECT_SOURCES
    ${SOURCE_PATH}/main.cpp
    ${SOURCE_PATH}/mainwindow.cpp
    # ${UI_PATH}/mainwindow.ui ${UI_PATH}/if_choose.ui
    ${SOURCE_PATH}/if_choose.cpp
    ${SOURCE_PATH}/if_loader.cpp
    ${SOURCE_PATH}/InterfaceManager.cpp
    ${SOURCE_PATH}/interface_widget.cpp
    ${SOURCE_PATH}/sessionmanager.cpp
    ${SOURCE_PATH}/packet_row.cpp
    ${SOURCE_PATH}/protocolparser.cpp
    ${SOURCE_PATH}/interfacerow.cpp
    ${SOURCE_PATH}/dns_utils.cpp
    ${SOURCE_PATH}/helpers.cpp
    ${SOURCE_PATH}/packettablemodel.cpp
    ${SOURCE_PATH}/protocoldetailtab.cpp
    ${SOURCE_PATH}/keyvaluepairwidget.cpp
    ${SOURCE_PATH}/uihelpers.cpp
    ${SOURCE_PATH}/hexview.cpp
    ${SOURCE_PATH}/sortingproxymodel.cpp
    ${SOURCE_PATH}/displayfilter.cpp
    ${SOURCE_PATH}/metainfopanel.cpp
    ${SOURCE_PATH}/ethernet.cpp
    ${SOURCE_PATH}/dnsquestionentry.cpp
    ${SOURCE_PATH}/dnsrecordssection.cpp
    ${SOURCE_PATH}/dnsanswerentry.cpp
    ${SOURCE_PATH}/pairfield.cpp
    ${SOURCE_PATH}/fieldinformationmodel.cpp
    ${SOURCE_PATH}/capturesettingsdialog.cpp
    ${SOURCE_PATH}/interfaceview.cpp
    ${SOURCE_PATH}/interfacemodel.cpp
    ${SOURCE_PATH}/interfaceitem.cpp
    ${SOURCE_PATH}/httpparser.cpp
    ${SOURCE_PATH}/httprequest.cpp
    ${SOURCE_PATH}/filesettingsview.cpp)

set(PROJECT_HEADERS
    ${HEADER_PATH}/ether.h
    ${HEADER_PATH}/macros.h
    ${HEADER_PATH}/proto.h
    ${HEADER_PATH}/proto_list.h
    ${HEADER_PATH}/proto_util.h
    ${HEADER_PATH}/types.h
    ${HEADER_PATH}/sessionmanager.h
    ${HEADER_PATH}/InterfaceManager.h
    ${HEADER_PATH}/interface_widget.h
    ${HEADER_PATH}/if_loader.h
    ${HEADER_PATH}/helpers.h
    ${HEADER_PATH}/if_choose.h
    ${HEADER_PATH}/mainwindow.h
    ${HEADER_PATH}/packet_row.h
    ${HEADER_PATH}/sm_fwd.h
    ${HEADER_PATH}/protocolparser.h
    ${HEADER_PATH}/interfacerow.h
    ${HEADER_PATH}/ports.h
    ${HEADER_PATH}/dns.h
    ${HEADER_PATH}/dns_utils.h
    ${HEADER_PATH}/packettablemodel.h
    ${HEADER_PATH}/protocoldetailtab.h
    ${HEADER_PATH}/keyvaluepairwidget.h
    ${HEADER_PATH}/protocolPropertyNames.h
    ${HEADER_PATH}/PropertyInfo.h
    ${HEADER_PATH}/TabInfo.h
    ${HEADER_PATH}/uihelpers.h
    ${HEADER_PATH}/hexview.h
    ${HEADER_PATH}/sortingproxymodel.h
    ${HEADER_PATH}/displayfilter.h
    ${HEADER_PATH}/metainfopanel.h
    ${HEADER_PATH}/ethernet.h
    ${HEADER_PATH}/dnsquestionentry.h
    ${HEADER_PATH}/dnsrecordssection.h
    ${HEADER_PATH}/dnsanswerentry.h
    ${HEADER_PATH}/pairfield.h
    ${HEADER_PATH}/fieldinformationmodel.h
    ${HEADER_PATH}/capturesettingsdialog.h
    ${HEADER_PATH}/interfaceview.h
    ${HEADER_PATH}/interfacemodel.h
    ${HEADER_PATH}/interfaceitem.h
    ${HEADER_PATH}/httpparser.h
    ${HEADER_PATH}/httprequest.h
    ${HEADER_PATH}/filesettingsview.h)

set(PROJECT_UI_FILES "${CMAKE_CURRENT_SOURCE_DIR}/src/ui/mainwindow.ui"
                     "${CMAKE_CURRENT_SOURCE_DIR}/src/ui/if_choose.ui")

set(QT_CREATOR_SKIP_MAINTENANCE_TOOL_PROVIDER ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
  qt_add_executable(
    NetSniffer
    MANUAL_FINALIZATION
    ${PROJECT_SOURCES}
    ${PROJECT_HEADERS}
    ${PROJECT_UI_FILES}
    src/ui/packetgeneralinfotab.h
    src/ui/packetgeneralinfotab.cpp
    src/ui/packetgeneralinfotab.ui
    src/ui/packetethernetinfotab.h
    src/ui/packetethernetinfotab.cpp
    src/ui/packetethernetinfotab.ui
    src/ui/packetipv4infotab.h
    src/ui/packetipv4infotab.cpp
    src/ui/packetipv4infotab.ui
    src/ui/packetarpinfotab.h
    src/ui/packetarpinfotab.cpp
    src/ui/packetarpinfotab.ui
    src/ui/packettcpinfotab.h
    src/ui/packettcpinfotab.cpp
    src/ui/packettcpinfotab.ui
    src/ui/packetudpinfotab.h
    src/ui/packetudpinfotab.cpp
    src/ui/packetudpinfotab.ui
    src/ui/packeticmpinfotab.h
    src/ui/packeticmpinfotab.cpp
    src/ui/packeticmpinfotab.ui
    src/ui/packetdnsinfotab.h
    src/ui/packetdnsinfotab.cpp
    src/ui/packetdnsinfotab.ui)
else()
  add_executable(NetSniffer ${PROJECT_SOURCES} ${PROJECT_HEADERS})
endif()

include(cmake/FindPcap.cmake)
add_subdirectory(QHexView)

if(QT_VERSION_MAJOR EQUAL 6)
  qt_finalize_executable(NetSniffer)
endif()
target_include_directories(NetSniffer PRIVATE ${HEADER_PATH})
target_link_libraries(NetSniffer PRIVATE Qt6::Widgets)
target_link_libraries(NetSniffer PRIVATE QHexView)
target_link_libraries(NetSniffer PRIVATE pcap::pcap)

message(STATUS "Default prefix for current user: ${CMAKE_INSTALL_PREFIX}")
