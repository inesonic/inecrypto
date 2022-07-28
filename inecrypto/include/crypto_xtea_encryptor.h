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
* This header defines the \ref Crypto::XteaEncryptor class.
***********************************************************************************************************************/

/* .. sphinx-project inecrypto */

#ifndef CRYPTO_XTEA_ENCRYPTOR_H
#define CRYPTO_XTEA_ENCRYPTOR_H

#include <QtGlobal>
#include <QIODevice>
#include <QByteArray>
#include <QObject>

#include <cstdint>

#include "crypto_encryptor.h"

class QObject;

namespace Crypto {
    /**
     * Class that provides support for XTEA encryption with a simple CBC algorithm.
     */
    class XteaEncryptor:public Encryptor {
        public:
            /**
             * The encryption key length, in bytes.
             */
            static constexpr unsigned keyLength = 16;

            /**
             * Array used to define the XTEA encryption key.
             */
            typedef std::uint8_t Keys[keyLength];

            /**
             * Constructor
             *
             * \param[in] parent Pointer to the parent object.  This device will also be used as the output device.
             */
            explicit XteaEncryptor(QIODevice* parent);

            /**
             * Constructor
             *
             * \param[in] parent Pointer to the parent object.
             */
            explicit XteaEncryptor(QObject* parent = Q_NULLPTR);

            /**
             * Constructor
             *
             * \param[in] keys   The default encryption keys to be used.
             *
             * \param[in] parent Pointer to the parent object.  This device will also be used as the output device.
             */
            explicit XteaEncryptor(const Keys& keys, QIODevice* parent);

            /**
             * Constructor
             *
             * \param[in] keys   The default encryption keys to be used.
             *
             * \param[in] parent Pointer to the parent object.
             */
            explicit XteaEncryptor(const Keys& keys, QObject* parent = Q_NULLPTR);

            ~XteaEncryptor() override;

            /**
             * Method you can use to obtain the length of the raw encryption key, in bytes.
             *
             * \return Returns the raw encryption key length, in bytes.
             */
            unsigned keyLengthInBytes() const override;

            /**
             * Method you can use to set the XTEA keys.
             *
             * \param[in] newKeys The new XTEA keys to be used.
             */
            void setKeys(const Keys& newKeys);

            /**
             * Method you can use to determine the encryption input chunk size.
             *
             * \return Returns the encryption chunk size.
             */
            unsigned inputChunkSize() const override;

        protected:
            /**
             * Method that is called to reset the encryption engine.
             */
            void resetEngine() override;

            /**
             * Method you should overload to perform encryption on a single chunk.  Data will always be supplied in
             * full chunks.
             *
             * \param[in]  inputData  Pointer to the unencrypted data to be processed.
             *
             * \param[out] outputData Pointer to the buffer to receive the resulting data.
             */
            void encryptChunk(const std::uint8_t* inputData, std::uint8_t* outputData) override;

        private:
            static constexpr std::uint32_t keyRollPolynomial   = 0x100D4E63;
            static constexpr std::uint32_t numberFeistelRounds = 64;
            static constexpr std::uint32_t xteaDelta           = 0x9E3779B9UL;

            /**
             * Method that is called to roll the active key value.
             *
             * \param[in] currentKey The current key value.
             *
             * \return Returns the new/modified key value.
             */
            static std::uint32_t rollKey(std::uint32_t currentKey);

            /**
             * The initial key values.
             */
            std::uint32_t initialKeys[keyLength / 4];

            /**
             * The current running keys.  We update the keys after each chunk.
             */
            std::uint32_t activeKeys[keyLength / 4];
    };
}

#endif
