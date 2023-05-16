cmake_minimum_required(VERSION 3.5)
project(oidc-pam LANGUAGES C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules/")


find_package(PAM REQUIRED)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

include_directories (
   ${PAM_INCLUDE_DIR}  ${OPENSSL_INCLUDE_DIR}
)

add_library(oidc-helpers STATIC config.c cjwt/cJSON.c auth.c log.c cjwt/base64.c cjwt/cjwt.c cjwt/jws_evp_openssl.c cjwt/print.c cjwt/utils.c)
target_link_libraries(oidc-helpers ${PAM_LIBRARIES} ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES}  ${OPENSSL_CRYPTO_LIBRARY})


add_library(oidc-pam SHARED oidc-pam.c )
set_target_properties(oidc-pam PROPERTIES PREFIX "")

target_link_libraries(oidc-pam oidc-helpers)

install(TARGETS oidc-pam DESTINATION /usr/lib/security)


SET(CPACK_GENERATOR "DEB;RPM")
SET(CPACK_DEBIAN_PACKAGE_MAINTAINER "ORNL")
SET(CPACK_RPM_PACKAGE_MAINTAINER "ORNL")

set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "1")
set(CPACK_PACKAGE_VERSION_PATCH "0")

set(CPACK_DEBIAN_PACKAGE_DEPENDS "curl")
set(CPACK_RPM_PACKAGE_DEPENDS "curl")

INCLUDE(CPack)

add_executable(oidc-pam-main main.c )
target_link_libraries(oidc-pam-main oidc-helpers)


add_executable(oidc-run-as-user run_as_user.c )
target_link_libraries(oidc-run-as-user oidc-helpers)
install(TARGETS oidc-run-as-user RUNTIME DESTINATION /usr/local/bin)
