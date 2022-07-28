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
* This file implements the \ref Crypto::XteaDecryptor class.
***********************************************************************************************************************/

#include <QObject>
#include <QIODevice>

#include <cstring>

#include "crypto_decryptor.h"
#include "crypto_xtea_decryptor.h"

namespace Crypto {
    XteaDecryptor::XteaDecryptor(QIODevice* parent):Decryptor(parent) {
        std::memset(initialKeys, 0, keyLength);
        std::memset(activeKeys, 0, keyLength);
    }


    XteaDecryptor::XteaDecryptor(QObject* parent):Decryptor(parent) {
        std::memset(initialKeys, 0, keyLength);
        std::memset(activeKeys, 0, keyLength);
    }


    XteaDecryptor::XteaDecryptor(const Keys& keys, QIODevice* parent):Decryptor(parent) {
        std::memcpy(initialKeys, keys, keyLength);
        std::memset(activeKeys, 0, keyLength);
    }


    XteaDecryptor::XteaDecryptor(const Keys& keys, QObject* parent):Decryptor(parent) {
        std::memcpy(initialKeys, keys, keyLength);
        std::memset(activeKeys, 0, keyLength);
    }


    XteaDecryptor::~XteaDecryptor() {
        std::memset(initialKeys, 0, keyLength);
        std::memset(activeKeys, 0, keyLength);
    }


    unsigned XteaDecryptor::keyLengthInBytes() const {
        return keyLength;
    }


    void XteaDecryptor::setKeys(const Keys& keys) {
        std::memcpy(initialKeys, keys, keyLength);
        std::memset(activeKeys, 0, keyLength);
    }


    unsigned XteaDecryptor::outputChunkSize() const {
        return 8;
    }


    void XteaDecryptor::resetEngine() {
        memcpy(activeKeys, initialKeys, keyLength);
    }


    void XteaDecryptor::decryptChunk(const std::uint8_t* inputData, std::uint8_t* outputData) {
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

        std::uint32_t sum = xteaDelta * numberFeistelRounds;
        for (unsigned j=0 ; j<numberFeistelRounds ; ++j) {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + activeKeys[(sum >> 11) & 3]);
            sum -= xteaDelta;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + activeKeys[sum & 3]);
        }

        outputData[0] = static_cast<unsigned char>(v0      );
        outputData[1] = static_cast<unsigned char>(v0 >>  8);
        outputData[2] = static_cast<unsigned char>(v0 >> 16);
        outputData[3] = static_cast<unsigned char>(v0 >> 24);
        outputData[4] = static_cast<unsigned char>(v1      );
        outputData[5] = static_cast<unsigned char>(v1 >>  8);
        outputData[6] = static_cast<unsigned char>(v1 >> 16);
        outputData[7] = static_cast<unsigned char>(v1 >> 24);

        activeKeys[0] = rollKey(activeKeys[0]) ^ v0;
        activeKeys[1] = rollKey(activeKeys[1]);
        activeKeys[2] = rollKey(activeKeys[2]);
        activeKeys[3] = rollKey(activeKeys[3]);
    }


    std::uint32_t XteaDecryptor::rollKey(std::uint32_t currentKey) {
        return currentKey & 0x80000000UL ? ((currentKey ^ keyRollPolynomial) << 1) | 0x00000001 : currentKey << 1;
    }
}
