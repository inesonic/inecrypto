/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This header defines the \ref Crypto::CipherBase class.
***********************************************************************************************************************/

/* .. sphinx-project inecrypto */

#ifndef CRYPTO_CIPHER_BASE_H
#define CRYPTO_CIPHER_BASE_H

#include <QString>
#include <QByteArray>

#include <cstdint>

class QObject;

namespace Crypto {
    /**
     * Pure virtual base class for all encryption and decryption engines.
     */
    class CipherBase {
        public:
            /**
             * Method you can use to obtain the length of the raw encryption key, in bytes.
             *
             * \return Returns the raw encryption key length, in bytes.
             */
            virtual unsigned keyLengthInBytes() const = 0;

            /**
             * Method you can use to convert an arbitrary byte array to a properly sized encryption key.
             *
             * \param[out] keyArray An array to hold the generated encryption key.
             *
             * \param[in]  byteArray The byte array to apply to the key array.
             */
            void generateKey(std::uint8_t* keyArray, const QByteArray& byteArray) const;

            /**
             * Method you can use to convert an arbitrary string to a properly sized encryption key.  The string will
             * be converted to a UTF-8 encoded byte array and then converted to a key.
             *
             * \param[out] keyArray An array to hold the generated encryption key.
             *
             * \param[in]  str      The string to be converted.
             */
            void generateKey(std::uint8_t* keyArray, const QString& str) const;
    };
}

#endif

