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
* This file implements the \ref Crypto::CypherBase class.
***********************************************************************************************************************/

#include <QString>
#include <QByteArray>

#include <cstring>

#include "crypto_cipher_base.h"

namespace Crypto {
    void CipherBase::generateKey(std::uint8_t* keyArray, const QByteArray& byteArray) const {
        unsigned keyLength = keyLengthInBytes();
        std::memset(keyArray, 0, keyLength);

        unsigned keyIndex    = 0;
        unsigned arrayLength = static_cast<unsigned>(byteArray.size());
        for (unsigned arrayIndex=0 ; arrayIndex<arrayLength ; ++arrayIndex) {
            keyArray[keyIndex] += byteArray.at(arrayIndex);
            keyIndex = (keyIndex + 1) % keyLength;
        }
    }


    void CipherBase::generateKey(std::uint8_t* keyArray, const QString& str) const {
        generateKey(keyArray, str.toUtf8());
    };
}


