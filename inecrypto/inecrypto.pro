##-*-makefile-*-########################################################################################################
# Copyright 2016 Inesonic, LLC
# All Rights Reserved
########################################################################################################################

TEMPLATE = lib

########################################################################################################################
# Basic build characteristics
#

QT += core
CONFIG += static c++14

win32 {
    # Windows generates a warning about potential overflow during operations on integer values.  While the warning may
    # make sense in some cases, it rapidly becomes excessive and is meaningless for this module.  We turn that warning
    # off here.

    QMAKE_CXXFLAGS_WARN_ON += -wd4307
}

########################################################################################################################
# Public includes
#

INCLUDEPATH += include
HEADERS = include/crypto_trng.h \
          include/crypto_hmac.h \
          include/crypto_helpers.h \
          include/crypto_cipher_base.h \
          include/crypto_encryptor.h \
          include/crypto_xtea_encryptor.h \
          include/crypto_aes_cbc_encryptor.h \
          include/crypto_decryptor.h \
          include/crypto_xtea_decryptor.h \
          include/crypto_aes_cbc_decryptor.h \
          include/crypto_crc_generator.h \

########################################################################################################################
# Source files
#

SOURCES = source/crypto_trng.cpp \
          source/crypto_hmac.cpp \
          source/crypto_helpers.cpp \
          source/crypto_cipher_base.cpp \
          source/crypto_encryptor.cpp \
          source/crypto_xtea_encryptor.cpp \
          source/crypto_aes_cbc_encryptor.cpp \
          source/crypto_decryptor.cpp \
          source/crypto_xtea_decryptor.cpp \
          source/crypto_aes_cbc_decryptor.cpp \

########################################################################################################################
# Add local version of Tiny-AES
#

TINYAES = ../tiny-aes-source-2020.08.08/

INCLUDEPATH += $${TINYAES}
HEADERS += $${TINYAES}/aes.h
SOURCES += $${TINYAES}/aes.c

########################################################################################################################
# Locate build intermediate and output products
#

TARGET = inecrypto

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
