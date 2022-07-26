/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This file implements tests of the Crypto AES (CBC) encryption/decryption functions.
***********************************************************************************************************************/

#include <QDebug>
#include <QString>
#include <QByteArray>
#include <QBuffer>
#include <QtTest/QtTest>

#include <cstdint>
#include <random>

#include <crypto_aes_cbc_encryptor.h>
#include <crypto_aes_cbc_decryptor.h>

#include "test_aes_cbc.h"

void TestAesCbc::testAesCbcEncryptDecryptBasic() {
    // Values below taken from the Tiny-AES test code.

    Crypto::AesCbcEncryptor::Keys keys = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    std::uint8_t rawExpected[] = {
        0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
        0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
        0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
        0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
    };

    Crypto::AesCbcEncryptor::IV iv  = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    std::uint8_t rawInput[]  = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

    QByteArray              input(reinterpret_cast<const char*>(rawInput), sizeof(rawInput));
    QByteArray              expected(reinterpret_cast<const char*>(rawExpected), sizeof(rawExpected));
    Crypto::AesCbcEncryptor encryptor(keys, iv);
    QByteArray              encrypted = encryptor.encrypt(input);

    QCOMPARE(encrypted, expected);

    Crypto::AesCbcDecryptor decryptor(keys, iv);
    QByteArray decrypted = decryptor.decrypt(encrypted);

    QCOMPARE(decrypted, input);
}


void TestAesCbc::testAesCbcEncryptDecryptFile() {
    QString t1("And close your eyes with holy dread For he on honey-dew hath fed, and drunk the milk of paradise.");

    Crypto::AesCbcEncryptor::Keys keys = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    QByteArray plainText = t1.toUtf8();
    while (plainText.size() % 16 != 0) {
        plainText.append('-');
    }

    QByteArray encrypted;
    QBuffer    encryptedBuffer(&encrypted);
    encryptedBuffer.open(QBuffer::OpenModeFlag::WriteOnly);

    Crypto::AesCbcEncryptor encryptor(keys, &encryptedBuffer);

    encryptor.open(Crypto::Encryptor::OpenModeFlag::WriteOnly);
    encryptor.write(plainText);
    encryptor.close();

    encryptedBuffer.close();
    encryptedBuffer.open(QBuffer::OpenModeFlag::ReadOnly);

    Crypto::AesCbcDecryptor decryptor(keys, &encryptedBuffer);
    decryptor.open(Crypto::AesCbcDecryptor::OpenModeFlag::ReadOnly);

    unsigned bytesAvailable = decryptor.bytesAvailable();
    QByteArray decrypted = decryptor.read(bytesAvailable);

    decryptor.close();

    QCOMPARE(decrypted, plainText);
}


void TestAesCbc::testAesCbcEncryptDecryptFuzz() {
    std::mt19937                    rng(0x12345678);
    std::uniform_int_distribution<> byteDistribution(0, 255);

    for (unsigned i=0 ; i<N ; ++i) {
        Crypto::AesCbcEncryptor::Keys keys;
        for (unsigned ki=0 ; ki<32 ; ++ki) {
            keys[ki] = byteDistribution(rng);
        }

        QByteArray plainText;
        unsigned   length = byteDistribution(rng) + 1;
        length = length + (16 - (length % 16));

        for (unsigned bi=0 ; bi<length ; ++bi) {
            plainText.append(static_cast<unsigned char>(byteDistribution(rng)));
        }

        Crypto::AesCbcEncryptor encryptor(keys);
        Crypto::AesCbcDecryptor decryptor(keys);

        QByteArray encrypted = encryptor.encrypt(plainText);
        QByteArray decrypted = decryptor.decrypt(encrypted);

        QCOMPARE(decrypted, plainText);
    }
}

