/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
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


