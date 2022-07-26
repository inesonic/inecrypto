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
* This file implements the \ref Hmac class.
***********************************************************************************************************************/

#include <QtGlobal>
#include <QByteArray>
#include <QCryptographicHash>

#include "crypto_hmac.h"

Crypto::Hmac::Hmac(
        QByteArray const&             newKey,
        Crypto::Hmac::Algorithm const newAlgorithm
    ):inner(static_cast<QCryptographicHash::Algorithm>(newAlgorithm)),
      outer(static_cast<QCryptographicHash::Algorithm>(newAlgorithm)) {
    initialize(newKey, newAlgorithm);
};


Crypto::Hmac::Hmac(
        QByteArray const&             newKey,
        QByteArray const&             newData,
        Crypto::Hmac::Algorithm const newAlgorithm
    ):inner(static_cast<QCryptographicHash::Algorithm>(newAlgorithm)),
      outer(static_cast<QCryptographicHash::Algorithm>(newAlgorithm)) {
    initialize(newKey, newAlgorithm);
    inner.addData(newData);
};


Crypto::Hmac::~Hmac() {
    inner.reset();
    outer.reset();
    zeroArray(paddedKey);
}


void Crypto::Hmac::reset() {
    inner.reset();
    outer.reset();
    inner.addData(xorArray(paddedKey, 0x36));
    outer.addData(xorArray(paddedKey, 0x5C));

    instanceSpent = false;
}


void Crypto::Hmac::reset(QByteArray const& newKey) {
    paddedKey = generatePaddedKey(newKey);
    reset();
}


QByteArray Crypto::Hmac::digest() {
    Q_ASSERT(!instanceSpent);
    instanceSpent = true;

    outer.addData(inner.result());
    return outer.result();
}


unsigned Crypto::Hmac::blockSize(Hmac::Algorithm const algorithm) {
    switch (algorithm) {
        case Crypto::Hmac::Md4:      return 512/8;
        case Crypto::Hmac::Md5:      return 512/8;
        case Crypto::Hmac::Sha1:     return 512/8;
        case Crypto::Hmac::Sha224:   return 512/8;
        case Crypto::Hmac::Sha256:   return 512/8;
        case Crypto::Hmac::Sha384:   return 1024/8;
        case Crypto::Hmac::Sha512:   return 1024/8;
        case Crypto::Hmac::Sha3_224: return 1152/8;
        case Crypto::Hmac::Sha3_256: return 1088/8;
        case Crypto::Hmac::Sha3_384: return 832/8;
        case Crypto::Hmac::Sha3_512: return 576/8;
        default: {
            Q_ASSERT(false);
            return 0;
        }
    }
}


unsigned Crypto::Hmac::digestSize(Hmac::Algorithm const algorithm) {
    switch (algorithm) {
        case Crypto::Hmac::Md4:      return 128/8;
        case Crypto::Hmac::Md5:      return 128/8;
        case Crypto::Hmac::Sha1:     return 160/8;
        case Crypto::Hmac::Sha224:   return 224/8;
        case Crypto::Hmac::Sha256:   return 256/8;
        case Crypto::Hmac::Sha384:   return 384/8;
        case Crypto::Hmac::Sha512:   return 512/8;
        case Crypto::Hmac::Sha3_224: return 224/8;
        case Crypto::Hmac::Sha3_256: return 256/8;
        case Crypto::Hmac::Sha3_384: return 384/8;
        case Crypto::Hmac::Sha3_512: return 512/8;
        default: {
            Q_ASSERT(false);
            return 0;
        }
    }
}

QByteArray Crypto::Hmac::xorArray(QByteArray const& data, quint8 const value) {
    QByteArray result = data;
    for (auto it=result.begin(), end=result.end() ; it!=end ; ++it) {
        (*it) ^= value;
    }

    return result;
}


QByteArray Crypto::Hmac::generatePaddedKey(QByteArray const& key) {
    unsigned keyLength = key.length();

    unsigned blockSize = Crypto::Hmac::blockSize(currentAlgorithm);

    if (blockSize < minimumBlockSize) {
        blockSize = forcedBlockSize;
    }

    QByteArray internalKey;
    if (keyLength < blockSize) {
        internalKey = key + QByteArray(blockSize - keyLength, 0x00);
    } else if (keyLength > blockSize) {
        Q_ASSERT(false); // Bug: Code below creates non-compliant hash.  Need to figure out why and fix.
        internalKey = QCryptographicHash::hash(key, static_cast<QCryptographicHash::Algorithm>(currentAlgorithm));
    } else {
        internalKey = key;
    }

    return internalKey;
}

void Crypto::Hmac::initialize(QByteArray const& key, Crypto::Hmac::Algorithm const newAlgorithm) {
    currentAlgorithm = newAlgorithm;
    reset(key);
}


void Crypto::Hmac::zeroArray(QByteArray& array) {
    for (auto it=array.begin(), end=array.end() ; it!=end ; ++it) {
        (*it) = 0;
    }
}
