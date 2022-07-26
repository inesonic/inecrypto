##-*-makefile-*-########################################################################################################
# Copyright 2016 Inesonic, LLC
# All Rights Reserved
########################################################################################################################

########################################################################################################################
# Basic build characteristics
#

TEMPLATE = app
QT += core testlib
CONFIG += testcase c++14

HEADERS = test_trng.h \
          test_crypto_helpers.h \
          test_crc_generator.h \
          test_xtea.h \
          test_aes_cbc.h \
          test_hmac.h

SOURCES = test_inecrypto.cpp \
          test_trng.cpp \
          test_crypto_helpers.cpp \
          test_crc_generator.cpp \
          test_xtea.cpp \
          test_aes_cbc.cpp \
          test_hmac.cpp

########################################################################################################################
# inecrypto library:
#

CRYPTO_BASE = $${OUT_PWD}/../inecrypto/
INCLUDEPATH = $${PWD}/../inecrypto/include/

unix {
    CONFIG(debug, debug|release) {
        LIBS += -L$${CRYPTO_BASE}/build/debug/ -linecrypto
        PRE_TARGETDEPS += $${CRYPTO_BASE}/build/debug/libinecrypto.a
    } else {
        LIBS += -L$${CRYPTO_BASE}/build/release/ -linecrypto
        PRE_TARGETDEPS += $${CRYPTO_BASE}/build/release/libinecrypto.a
    }
}

win32 {
    CONFIG(debug, debug|release) {
        LIBS += $${CRYPTO_BASE}/build/Debug/inecrypto.lib
        PRE_TARGETDEPS += $${CRYPTO_BASE}/build/Debug/inecrypto.lib
    } else {
        LIBS += $${CRYPTO_BASE}/build/Release/inecrypto.lib
        PRE_TARGETDEPS += $${CRYPTO_BASE}/build/Release/inecrypto.lib
    }
}

########################################################################################################################
# Libraries
#

#include("../inecrypto.pri")
#include("$${SOURCE_ROOT}/libraries/ineutil/ineutil.pri")
#include("$${SOURCE_ROOT}/third_party/operating_system.pri")

########################################################################################################################
# Locate build intermediate and output products
#

TARGET = test_inecrypto

CONFIG(debug, debug|release) {
    unix:DESTDIR = build/debug
    win32:DESTDIR = build/Debug
} else {
    unix:DESTDIR = build/release
    win32:DESTDIR = build/Release
}

OBJECTS_DIR = $${DESTDIR}/objects
MOC_DIR = $${DESTDIR}/moc
RCC_DIR = $${DESTDIR}/rcc
UI_DIR = $${DESTDIR}/ui
