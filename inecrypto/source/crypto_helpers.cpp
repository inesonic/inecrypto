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
* This file implements a small set of useful functions.
***********************************************************************************************************************/

#include <QtGlobal>
#include <QByteArray>
#include <QString>
#include <QRandomGenerator>

#include <cstdint>
#include <cstring>

#include "crypto_helpers.h"

void Crypto::scrub(QByteArray& array) {
    char* d = array.data();
    std::memset(d, 0, array.size());
}


void Crypto::scrub(QString& str) {
    // Can't use memset on the string content because QChar is not a POD type.
    unsigned stringLength = str.length();
    for (unsigned i=0 ; i<stringLength ; ++i) {
        str[i] = QChar(0);
    }
}


QByteArray Crypto::generateRandomArray(unsigned arrayLength) {
     QByteArray result(static_cast<int>(arrayLength), 0);
     char*      d = result.data();
     std::uint64_t r = 0;
     for (unsigned i=0 ; i<arrayLength ; ++i) {
         if ((i % 8) == 0) {
             r = QRandomGenerator::global()->generate64();
         }
         d[i] = static_cast<char>(r);
         r >>= 8;
     }

     return result;
}


QByteArray& Crypto::stripByteArray(QByteArray& array) {
    unsigned idealLength = array.length();
    while (idealLength > 0 && static_cast<quint8>(array[idealLength-1]) == 0) {
        --idealLength;
    }

    array.truncate(idealLength);

    return array;
}


unsigned Crypto::numberOnes64(std::uint64_t value) {
    std::uint64_t x = value;

    x -= ((x >> 1) & 0x5555555555555555ULL);
    x = (((x >> 2) & 0x3333333333333333ULL) + (x & 0x3333333333333333ULL));
    x = (((x >> 4) + x) & 0x0F0F0F0F0F0F0F0FULL);
    x += (x >> 8);
    x += (x >> 16);
    x += (x >> 32);

    return(x & 0x0000007f);
}


int Crypto::msbLocation32(std::uint32_t value) {
    int msbLocation = 0;

    if (value) {
        unsigned adjustment = 32;
        std::uint32_t runningValue = value;

        while (adjustment) {
            std::uint32_t mask = ((1ULL << adjustment) - 1) << adjustment;
            if (runningValue & mask) {
                runningValue >>= adjustment;
                msbLocation += adjustment;
            }

            adjustment >>= 1;
        }
    } else {
        msbLocation = -1;
    }

    return msbLocation;
}


int Crypto::msbLocation64(std::uint64_t value) {
    int msbLocation = 0;

    if (value) {
        unsigned adjustment = 64;
        std::uint64_t runningValue = value;

        while (adjustment) {
            std::uint64_t mask = ((1ULL << adjustment) - 1) << adjustment;
            if (runningValue & mask) {
                runningValue >>= adjustment;
                msbLocation += adjustment;
            }

            adjustment >>= 1;
        }
    } else {
        msbLocation = -1;
    }

    return msbLocation;
}
