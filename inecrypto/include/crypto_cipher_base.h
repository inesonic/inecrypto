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

