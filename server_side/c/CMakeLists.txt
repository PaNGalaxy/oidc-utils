cmake_minimum_required(VERSION 3.5)
project(oidc-pam LANGUAGES C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules/")


find_package(PAM REQUIRED)
find_package(CURL REQUIRED)

include_directories (
   ${PAM_INCLUDE_DIR}
)

add_library(oidc-pam SHARED oidc-pam.c config.c json/cJSON.c auth.c log.c)
set_target_properties(oidc-pam PROPERTIES PREFIX "")

target_link_libraries(oidc-pam ${PAM_LIBRARIES} ${CURL_LIBRARIES})

install(TARGETS oidc-pam DESTINATION /usr/lib/security)

SET(CPACK_GENERATOR "DEB")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "ORNL")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "1")
set(CPACK_PACKAGE_VERSION_PATCH "0")

set(CPACK_DEBIAN_PACKAGE_DEPENDS "curl")

INCLUDE(CPack)

add_executable(oidc-pam-main main.c config.c  json/cJSON.c auth.c log.c)
target_link_libraries(oidc-pam-main ${PAM_LIBRARIES} ${CURL_LIBRARIES})
