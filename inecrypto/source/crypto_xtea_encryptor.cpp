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
* This file implements tje \ref Crypto::XteaEncryptor class.
***********************************************************************************************************************/

#include <QObject>
#include <QIODevice>

#include <cstring>

#include "crypto_encryptor.h"
#include "crypto_xtea_encryptor.h"

namespace Crypto {
    XteaEncryptor::XteaEncryptor(QIODevice* parent):Encryptor(parent) {
        std::memset(initialKeys, 0, keyLength);
        std::memset(activeKeys, 0, keyLength);
    }


    XteaEncryptor::XteaEncryptor(QObject* parent):Encryptor(parent) {
        std::memset(initialKeys, 0, keyLength);
        std::memset(activeKeys, 0, keyLength);
    }


    XteaEncryptor::XteaEncryptor(const Keys& keys, QIODevice* parent):Encryptor(parent) {
        std::memcpy(initialKeys, keys, keyLength);
        std::memset(activeKeys, 0, keyLength);
    }


    XteaEncryptor::XteaEncryptor(const Keys& keys, QObject* parent):Encryptor(parent) {
        std::memcpy(initialKeys, keys, keyLength);
        std::memset(activeKeys, 0, keyLength);
    }


    XteaEncryptor::~XteaEncryptor() {
        std::memset(initialKeys, 0, keyLength);
        std::memset(activeKeys, 0, keyLength);
    }


    unsigned XteaEncryptor::keyLengthInBytes() const {
        return keyLength;
    }


    void XteaEncryptor::setKeys(const Keys& keys) {
        std::memcpy(initialKeys, keys, keyLength);
        std::memset(activeKeys, 0, keyLength);
    }


    unsigned XteaEncryptor::inputChunkSize() const {
        return 8;
    }


    void XteaEncryptor::resetEngine() {
        memcpy(activeKeys, initialKeys, keyLength);
    }


    void XteaEncryptor::encryptChunk(const std::uint8_t* inputData, std::uint8_t* outputData) {
        // The algorithm has been shamelessly lifted from:
        //
        //   http://en.wikipedia.org/wiki/XTEA
        //
        // We've modify the algorithm to roll our keys before each cycle so that the key in each cycle changes.

        std::uint32_t v0 = (
              (inputData[0]      )
            | (inputData[1] <<  8)
            | (inputData[2] << 16)
            | (inputData[3] << 24)
        );

        std::uint32_t v1 = (
              (inputData[4]      )
            | (inputData[5] <<  8)
            | (inputData[6] << 16)
            | (inputData[7] << 24)
        );

        std::uint32_t input_v0 = v0;

        std::uint32_t sum = 0;
        for (unsigned j=0 ; j<numberFeistelRounds ; ++j) {
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + activeKeys[sum & 3]);
            sum += xteaDelta;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + activeKeys[(sum >> 11) & 3]);
        }

        outputData[0] = static_cast<std::uint8_t>(v0      );
        outputData[1] = static_cast<std::uint8_t>(v0 >>  8);
        outputData[2] = static_cast<std::uint8_t>(v0 >> 16);
        outputData[3] = static_cast<std::uint8_t>(v0 >> 24);
        outputData[4] = static_cast<std::uint8_t>(v1      );
        outputData[5] = static_cast<std::uint8_t>(v1 >>  8);
        outputData[6] = static_cast<std::uint8_t>(v1 >> 16);
        outputData[7] = static_cast<std::uint8_t>(v1 >> 24);

        activeKeys[0] = rollKey(activeKeys[0]) ^ input_v0;
        activeKeys[1] = rollKey(activeKeys[1]);
        activeKeys[2] = rollKey(activeKeys[2]);
        activeKeys[3] = rollKey(activeKeys[3]);
    }


    std::uint32_t XteaEncryptor::rollKey(std::uint32_t currentKey) {
        return currentKey & 0x80000000UL ? ((currentKey ^ keyRollPolynomial) << 1) | 0x00000001 : currentKey << 1;
    }
}
