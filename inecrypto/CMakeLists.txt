##-*-cmake-*-###########################################################################################################
# Copyright 2016 - 2022 Inesonic, LLC
#
# MIT License:
#   Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
#   documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
#   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
#   permit persons to whom the Software is furnished to do so, subject to the following conditions:
#   
#   The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
#   Software.
#   
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
#   WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
#   OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
#   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
########################################################################################################################

cmake_minimum_required(VERSION 3.16.3)
project(inecrypto LANGUAGES CXX)

SET(CMAKE_CXX_STANDARD 14)
if(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -wd4307")
endif()

# Allow building either static or shared libraries
set(${PROJECT_NAME}_TYPE CACHE STRING "Static or shared library")
set_property(CACHE ${PROJECT_NAME}_TYPE PROPERTY STRINGS "SHARED;STATIC")
IF(NOT ${${PROJECT_NAME}_TYPE})
    SET(${PROJECT_NAME}_TYPE STATIC)
ENDIF()

find_package(Qt5 COMPONENTS Core)
find_package(Qt5 COMPONENTS Test)

set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_library(${PROJECT_NAME} ${${PROJECT_NAME}_TYPE}
            source/crypto_trng.cpp
            source/crypto_hmac.cpp
            source/crypto_helpers.cpp
            source/crypto_cipher_base.cpp
            source/crypto_encryptor.cpp
            source/crypto_xtea_encryptor.cpp
            source/crypto_aes_cbc_encryptor.cpp
            source/crypto_decryptor.cpp
            source/crypto_xtea_decryptor.cpp
            source/crypto_aes_cbc_decryptor.cpp
	    ../tiny-aes-source-2020.08.08/aes.c
)

set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE 1)

target_include_directories(${PROJECT_NAME} PUBLIC "include")
include_directories("include")
include_directories("../tiny-aes-source-2020.08.08/")
target_link_libraries(${PROJECT_NAME} Qt5::Core)

install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)

install(FILES include/crypto_trng.h DESTINATION include)
install(FILES include/crypto_hmac.h DESTINATION include)
install(FILES include/crypto_helpers.h DESTINATION include)
install(FILES include/crypto_cipher_base.h DESTINATION include)
install(FILES include/crypto_encryptor.h DESTINATION include)
install(FILES include/crypto_xtea_encryptor.h DESTINATION include)
install(FILES include/crypto_aes_cbc_encryptor.h DESTINATION include)
install(FILES include/crypto_decryptor.h DESTINATION include)
install(FILES include/crypto_xtea_decryptor.h DESTINATION include)
install(FILES include/crypto_aes_cbc_decryptor.h DESTINATION include)
install(FILES include/crypto_crc_generator.h DESTINATION include)

