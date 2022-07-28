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
* This file implements tje \ref Crypto::AesCbcEncryptor class.
***********************************************************************************************************************/

#include <QObject>
#include <QIODevice>

#include <cstring>

extern "C" {
    #include <aes.h>
}

#include "crypto_encryptor.h"
#include "crypto_aes_cbc_encryptor.h"

namespace Crypto {
    AesCbcEncryptor::AesCbcEncryptor(QIODevice* parent):Encryptor(parent) {
        std::memset(initialKeys, 0, keyLength);
        initializeIV();
        context = Q_NULLPTR;
    }


    AesCbcEncryptor::AesCbcEncryptor(QObject* parent):Encryptor(parent) {
        std::memset(initialKeys, 0, keyLength);
        initializeIV();

        context = Q_NULLPTR;
    }


    AesCbcEncryptor::AesCbcEncryptor(const AesCbcEncryptor::Keys& keys, QIODevice* parent):Encryptor(parent) {
        std::memcpy(initialKeys, keys, keyLength);
        initializeIV();

        context = Q_NULLPTR;
    }


    AesCbcEncryptor::AesCbcEncryptor(const AesCbcEncryptor::Keys& keys, QObject* parent):Encryptor(parent) {
        std::memcpy(initialKeys, keys, keyLength);
        initializeIV();

        context = Q_NULLPTR;
    }


    AesCbcEncryptor::AesCbcEncryptor(
            const AesCbcEncryptor::Keys& keys,
            const AesCbcEncryptor::IV&   iv,
            QIODevice*                   parent
        ):Encryptor(
            parent
        ) {
        std::memcpy(initialKeys, keys, keyLength);
        std::memcpy(initialIV, iv, ivLength);

        context = Q_NULLPTR;
    }


    AesCbcEncryptor::AesCbcEncryptor(
            const AesCbcEncryptor::Keys& keys,
            const AesCbcEncryptor::IV&   iv,
            QObject*                     parent
        ):Encryptor(
            parent
        ) {
        std::memcpy(initialKeys, keys, keyLength);
        std::memcpy(initialIV, iv, ivLength);

        context = Q_NULLPTR;
    }


    AesCbcEncryptor::AesCbcEncryptor(
            const AesCbcEncryptor::Keys& keys,
            const std::uint8_t*          iv,
            QIODevice*                   parent
        ):Encryptor(
            parent
        ) {
        std::memcpy(initialKeys, keys, keyLength);
        std::memcpy(initialIV, iv, ivLength);

        context = Q_NULLPTR;
    }


    AesCbcEncryptor::AesCbcEncryptor(
            const AesCbcEncryptor::Keys& keys,
            const std::uint8_t*          iv,
            QObject*                     parent
        ):Encryptor(
            parent
        ) {
        std::memcpy(initialKeys, keys, keyLength);
        std::memcpy(initialIV, iv, ivLength);

        context = Q_NULLPTR;
    }


    AesCbcEncryptor::~AesCbcEncryptor() {
        std::memset(initialKeys, 0, keyLength);
        std::memset(initialIV, 0, ivLength);

        if (context != Q_NULLPTR) {
            memset(context, 0, sizeof(AES_ctx));
            delete context;
        }
    }


    unsigned AesCbcEncryptor::keyLengthInBytes() const {
        return keyLength;
    }


    void AesCbcEncryptor::setKeys(const Keys& keys) {
        std::memcpy(initialKeys, keys, keyLength);
    }


    void AesCbcEncryptor::setIV(const IV& newIV) {
        std::memcpy(initialIV, newIV, ivLength);
    }


    unsigned AesCbcEncryptor::inputChunkSize() const {
        return AES_BLOCKLEN;
    }


    void AesCbcEncryptor::resetEngine() {
        if (context == Q_NULLPTR) {
            context = new AES_ctx;
        }

        AES_init_ctx_iv(context, initialKeys, initialIV);
    }


    void AesCbcEncryptor::encryptChunk(const std::uint8_t* inputData, std::uint8_t* outputData) {
        std::memcpy(outputData, inputData, AES_BLOCKLEN);
        AES_CBC_encrypt_buffer(context, outputData, AES_BLOCKLEN);
    }


    void AesCbcEncryptor::initializeIV() {
        // We just want a little entropy in our IV so we use a super-simple PRNG
        std::uint8_t seeds[4] = { 251, 241, 239, 233 };
        for (unsigned i=0 ; i<ivLength ; ++i) {
            std::uint8_t newSeed = seeds[0] + seeds[1] + seeds[2] + seeds[3] + 1;
            seeds[3] = seeds[2];
            seeds[2] = seeds[1];
            seeds[1] = seeds[0];
            seeds[0] = newSeed;

            initialIV[i] = newSeed;
        }
    }
}
