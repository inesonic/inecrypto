/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 - 2022 Inesonic, LLC.
*
* MIT License:
*   Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
*   documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
*   rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
*   permit persons to whom the Software is furnished to do so, subject to the following conditions:
*   
*   The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
*   Software.
*   
*   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
*   WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
*   OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
*   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
********************************************************************************************************************//**
* \file
*
* This file implements tests of the Crypto XTEA encryption/decryption functions.
***********************************************************************************************************************/

#include <QDebug>
#include <QString>
#include <QByteArray>
#include <QBuffer>
#include <QtTest/QtTest>

#include <random>

#include <crypto_xtea_encryptor.h>
#include <crypto_xtea_decryptor.h>

#include "test_xtea.h"

void TestXtea::testXteaEncryptDecryptBasic() {
    QString t1("And close your eyes with holy dread For he on honey-dew hath fed, and drunk the milk of paradise.");

    Crypto::XteaEncryptor::Keys keys = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    QByteArray            plainText = t1.toUtf8();
    Crypto::XteaEncryptor encryptor(keys);

    while (plainText.size() % encryptor.inputChunkSize() != 0) {
        plainText.append('-');
    }

    QByteArray encrypted = encryptor.encrypt(plainText);

    Crypto::XteaDecryptor decryptor(keys);
    QByteArray decrypted = decryptor.decrypt(encrypted);

    QCOMPARE(decrypted, plainText);
}


void TestXtea::testXteaEncryptDecryptFile() {
    QString t1("And close your eyes with holy dread For he on honey-dew hath fed, and drunk the milk of paradise.");

    Crypto::XteaEncryptor::Keys keys = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };

    QByteArray plainText = t1.toUtf8();
    while (plainText.size() % 8 != 0) {
        plainText.append('-');
    }

    QByteArray encrypted;
    QBuffer    encryptedBuffer(&encrypted);
    encryptedBuffer.open(QBuffer::OpenModeFlag::WriteOnly);

    Crypto::XteaEncryptor encryptor(keys, &encryptedBuffer);

    encryptor.open(Crypto::Encryptor::OpenModeFlag::WriteOnly);
    encryptor.write(plainText);
    encryptor.close();

    encryptedBuffer.close();
    encryptedBuffer.open(QBuffer::OpenModeFlag::ReadOnly);

    Crypto::XteaDecryptor decryptor(keys, &encryptedBuffer);
    decryptor.open(Crypto::XteaDecryptor::OpenModeFlag::ReadOnly);

    unsigned bytesAvailable = decryptor.bytesAvailable();
    QByteArray decrypted = decryptor.read(bytesAvailable);

    decryptor.close();

    QCOMPARE(decrypted, plainText);
}


void TestXtea::testXteaEncryptDecryptFuzz() {
    std::mt19937                    rng(0x12345678);
    std::uniform_int_distribution<> byteDistribution(0, 255);

    for (unsigned i=0 ; i<N ; ++i) {
        Crypto::XteaEncryptor::Keys keys;
        for (unsigned ki=0 ; ki<8 ; ++ki) {
            keys[ki] = byteDistribution(rng);
        }

        QByteArray plainText;
        unsigned   length = byteDistribution(rng) + 1;
        length = length + (8 - (length % 8));

        for (unsigned bi=0 ; bi<length ; ++bi) {
            plainText.append(static_cast<unsigned char>(byteDistribution(rng)));
        }

        Crypto::XteaEncryptor encryptor(keys);
        Crypto::XteaDecryptor decryptor(keys);

        QByteArray encrypted = encryptor.encrypt(plainText);
        QByteArray decrypted = decryptor.decrypt(encrypted);

        QCOMPARE(decrypted, plainText);
    }
}

