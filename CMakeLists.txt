cmake_minimum_required(VERSION 3.5)

project(NetSniffer VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(USER_PERSONAL_APPDATA_DIR "$ENV{USERPROFILE}\\AppData\\Local")
set(PCAP_GENERAL_FOLDER "${USER_PERSONAL_APPDATA_DIR}\\npcap-sdk")
set(PCAP_INCLUDE_FOLDER "${PCAP_GENERAL_FOLDER}\\Include")
set(PCAP_LIB_FOLDER "${PCAP_GENERAL_FOLDER}\\Lib\\x64\\")

set(SOURCE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(UI_PATH ${SOURCE_PATH}/ui)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_AUTOUIC_SEARCH_PATHS ${UI_PATH})



set(APP_BINARY_DIR "${USER_PERSONAL_APPDATA_DIR}\\netsniffer")
set(ICONS_DIR "${CMAKE_SOURCE_DIR}\\icons")


set(HEX_VIEW_DIR ${CMAKE_CURRENT_SOURCE_DIR}/QHexView)
set(INCLUDE_MEMORY_BUF ${HEX_VIEW_DIR}/document/buffer)

set(PROJECT_SOURCES
        ${SOURCE_PATH}/main.cpp
        ${SOURCE_PATH}/mainwindow.cpp
        ${SOURCE_PATH}/mainwindow.h
        ${UI_PATH}/mainwindow.ui
        ${UI_PATH}/if_choose.ui
        ${SOURCE_PATH}/if_choose.cpp
        ${SOURCE_PATH}/if_choose.h
        ${SOURCE_PATH}/if_loader.cpp
        ${SOURCE_PATH}/if_loader.h
        ${SOURCE_PATH}/helpers.h
        ${SOURCE_PATH}/InterfaceManager.cpp
        ${SOURCE_PATH}/InterfaceManager.h
        ${SOURCE_PATH}/interface_widget.h
        ${SOURCE_PATH}/interface_widget.cpp
        ${SOURCE_PATH}/sessionmanager.h
        ${SOURCE_PATH}/sessionmanager.cpp
        ${SOURCE_PATH}/ether.h
        ${SOURCE_PATH}/macros.h
        ${SOURCE_PATH}/proto.h
        ${SOURCE_PATH}/proto_list.h
        ${SOURCE_PATH}/proto_util.h
        ${SOURCE_PATH}/types.h
    )



if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(NetSniffer
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
        src/packet_row.h src/packet_row.cpp
        src/sm_fwd.h
        src/protocolparser.h src/protocolparser.cpp
        src/interfacerow.h src/interfacerow.cpp
        src/ports.h
        src/dns.h
        src/dns_utils.h src/dns_utils.cpp
        src/helpers.cpp
        src/packettablemodel.h src/packettablemodel.cpp
        src/protocoldetailtab.h src/protocoldetailtab.cpp
        src/keyvaluepairwidget.h src/keyvaluepairwidget.cpp
        src/protocolPropertyNames.h
        src/PropertyInfo.h
        src/TabInfo.h
        src/uihelpers.h src/uihelpers.cpp
        src/hexview.h src/hexview.cpp
        src/sortingproxymodel.h src/sortingproxymodel.cpp
        src/displayfilter.h src/displayfilter.cpp
        src/metainfopanel.h src/metainfopanel.cpp
        src/ethernet.h src/ethernet.cpp
        src/dnsquestionentry.h src/dnsquestionentry.cpp
        src/dnsrecordssection.h src/dnsrecordssection.cpp
        src/dnsanswerentry.h src/dnsanswerentry.cpp
        src/pairfield.h src/pairfield.cpp
        src/fieldinformationmodel.h src/fieldinformationmodel.cpp
        src/capturesettingsdialog.h src/capturesettingsdialog.cpp
        src/interfaceview.h src/interfaceview.cpp
        src/interfacemodel.h src/interfacemodel.cpp
        src/interfaceitem.h src/interfaceitem.cpp
        src/httpparser.h src/httpparser.cpp
        src/httprequest.h src/httprequest.cpp
        src/filesettingsview.h src/filesettingsview.cpp



    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET NetSniffer APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
        add_library(NetSniffer SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(NetSniffer
            ${PROJECT_SOURCES}
        )
    endif()
endif()

target_include_directories(NetSniffer PRIVATE ${PCAP_INCLUDE_FOLDER})
target_link_libraries(NetSniffer PRIVATE Qt${QT_VERSION_MAJOR}::Widgets ${PCAP_LIB_FOLDER}Packet.lib ${PCAP_LIB_FOLDER}wpcap.lib)

include(../OwnHexView/CMakeLists.txt)


target_link_libraries(NetSniffer PRIVATE ${CMAKE_SOURCE_DIR}/build/OwnHexView.lib)
target_include_directories(NetSniffer PRIVATE ${OWN_INCLUDE})

include(FetchContent)

set(CMAKE_INSTALL_PREFIX ${INSTALL_FOLDER_NAME})
# LLHttp library for HTTP parse
FetchContent_Declare(
  llhttp
  GIT_REPOSITORY https://github.com/nodejs/llhttp.git
  GIT_TAG       610a87d755f6bae466cd871c2ba97574ccac5483
)

FetchContent_MakeAvailable(llhttp)

# target_link_libraries(${PROJECT_NAME} PRIVATE llhttp::llhttp)
include_directories(${PROJECT_NAME} PUBLIC ${llhttp_SOURCE_DIR}/include)
target_link_libraries(NetSniffer PRIVATE llhttp_shared)

set(CMAKE_INSTALL_PREFIX ${APP_BINARY_DIR})
install(TARGETS NetSniffer llhttp_shared
        RUNTIME DESTINATION bin)

install(DIRECTORY ${ICONS_DIR} DESTINATION ${CMAKE_INSTALL_PREFIX})

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(NetSniffer)
endif()
