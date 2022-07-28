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
* This header defines the \ref Crypto::AesCbcEncryptor class.
***********************************************************************************************************************/

/* .. sphinx-project inecrypto */

#ifndef CRYPTO_AES_CBC_ENCRYPTOR_H
#define CRYPTO_AES_CBC_ENCRYPTOR_H

#include <QtGlobal>
#include <QIODevice>
#include <QByteArray>
#include <QObject>

#include <cstdint>

#include "crypto_encryptor.h"

class QObject;

struct AES_ctx;

namespace Crypto {
    /**
     * Class that provides support for AES-256 encryption with CBC.
     */
    class AesCbcEncryptor:public Encryptor {
        public:
            /**
             * The encryption key length, in bytes.
             */
            static constexpr unsigned keyLength = 32;

            /**
             * The IV length, in bytes.
             */
            static constexpr unsigned ivLength = 16;

            /**
             * Array used to define the AES encryption key.
             */
            typedef std::uint8_t Keys[keyLength];

            /**
             * Array used to define the AES IV.
             */
            typedef std::uint8_t IV[ivLength];

            /**
             * Constructor
             *
             * \param[in] parent Pointer to the parent object.  This device will also be used as the output device.
             */
            explicit AesCbcEncryptor(QIODevice* parent);

            /**
             * Constructor
             *
             * \param[in] parent Pointer to the parent object.
             */
            explicit AesCbcEncryptor(QObject* parent = Q_NULLPTR);

            /**
             * Constructor
             *
             * \param[in] keys   The default encryption keys to be used.
             *
             * \param[in] parent Pointer to the parent object.  This device will also be used as the output device.
             */
            explicit AesCbcEncryptor(const Keys& keys, QIODevice* parent);

            /**
             * Constructor
             *
             * \param[in] keys   The default encryption keys to be used.
             *
             * \param[in] parent Pointer to the parent object.
             */
            explicit AesCbcEncryptor(const Keys& keys, QObject* parent = Q_NULLPTR);

            /**
             * Constructor
             *
             * \param[in] keys   The default encryption keys to be used.
             *
             * \param[in] iv     The encryptor initialization vector.
             *
             * \param[in] parent Pointer to the parent object.  This device will also be used as the output device.
             */
            AesCbcEncryptor(const Keys& keys, const IV& iv, QIODevice* parent);

            /**
             * Constructor
             *
             * \param[in] keys   The default encryption keys to be used.
             *
             * \param[in] iv     The encryptor initialization vector.
             *
             * \param[in] parent Pointer to the parent object.
             */
            AesCbcEncryptor(const Keys& keys, const IV& iv, QObject* parent = Q_NULLPTR);

            /**
             * Constructor
             *
             * \param[in] keys   The default encryption keys to be used.
             *
             * \param[in] iv     The encryptor initialization vector.
             *
             * \param[in] parent Pointer to the parent object.  This device will also be used as the output device.
             */
            AesCbcEncryptor(const Keys& keys, const std::uint8_t* iv, QIODevice* parent);

            /**
             * Constructor
             *
             * \param[in] keys   The default encryption keys to be used.
             *
             * \param[in] iv     The encryptor initialization vector.
             *
             * \param[in] parent Pointer to the parent object.
             */
            AesCbcEncryptor(const Keys& keys, const std::uint8_t* iv, QObject* parent = Q_NULLPTR);

            ~AesCbcEncryptor() override;

            /**
             * Method you can use to obtain the length of the raw encryption key, in bytes.
             *
             * \return Returns the raw encryption key length, in bytes.
             */
            unsigned keyLengthInBytes() const override;

            /**
             * Method you can use to set the AES keys.
             *
             * \param[in] newKeys The new AES keys to be used.
             */
            void setKeys(const Keys& newKeys);

            /**
             * Method you can use to set the AES initialization vector.
             *
             * \param[in] newIV The new AES initialization vector to be used.
             */
            void setIV(const IV& newIV);

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
            /**
             * Method that initializes the IV to a default state.
             */
            void initializeIV();

            /**
             * The initial key values.
             */
            Keys initialKeys;

            /**
             * The initial IV.
             */
            IV initialIV;

            /**
             * The encryption pointer.
             */
            AES_ctx* context;
    };
}

#endif
