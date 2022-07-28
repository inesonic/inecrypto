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
* This header defines the \ref Crypto::Encryptor class.
***********************************************************************************************************************/

/* .. sphinx-project inecrypto */

#ifndef CRYPTO_ENCRYPTOR_H
#define CRYPTO_ENCRYPTOR_H

#include <QtGlobal>
#include <QIODevice>
#include <QByteArray>
#include <QObject>

#include <cstdint>

#include "crypto_cipher_base.h"

class QObject;

namespace Crypto {
    /**
     * Common base class for encryption engines.  This class provides an API that allows both in-place encryption of
     * a block as well as a QIODevice compatible streaming API.  You can not use both API's simulteanously on the
     * same class instance.
     *
     * Derived classes can use this base class to simplify implementing encryption engines.
     */
    class Encryptor:public QIODevice, public CipherBase {
        public:
            /**
             * Constructor
             *
             * \param[in] parent Pointer to the parent object.  This device will also be used as the output device.
             */
            explicit Encryptor(QIODevice* parent = Q_NULLPTR);

            /**
             * Constructor
             *
             * \param[in] parent Pointer to the parent object.
             */
            explicit Encryptor(QObject* parent = Q_NULLPTR);

            ~Encryptor() override;

            /**
             * Method you can call to perform in-place encryption of a data buffer.
             *
             * \param[in] inputBuffer The buffer to be encrypted.
             *
             * \return Returns an encrypted version of the supplied buffer.
             */
            QByteArray encrypt(const QByteArray& inputBuffer);

            /**
             * Method you can use to set the destination device.
             *
             * \param[in] outputDevice The device to receive the encrypted stream.  This class does
             *                         not take ownership of the output device.
             */
            void setOutputDevice(QIODevice* outputDevice);

            /**
             * Method you can use to determine the current destination device.
             *
             * \return Returns a pointer to the output device.
             */
            QIODevice* outputDevice() const;

            /**
             * Method you can use to open up a new file for writing.
             *
             * \param[in] openMode The file open mode.  This method will return false if this value is not a writable
             *                     mode.
             *
             * \return Returns true on success, returns false on error.
             */
            bool open(Encryptor::OpenMode openMode) override;

            /**
             * Method you can use to flush the current encryption buffer.  This method will append
             * a PKCS#7 sequence, if needed, and then flush the internal buffer.
             *
             * \return Returns true on success.  Returns false on error.
             */
            bool flush();

            /**
             * Method you can use to add a random additional pad to the encrypted output.  This will also cause the
             * encryptor to flush any pending output.
             *
             * \return Returns true on success.  Returns false on error.
             */
            bool flushAndPad();

            /**
             * Method you can use to determine if this is a sequential device.
             *
             * \return Returns true if this is a sequential device.  Returns false if this is not a sequential device.
             *         this method always returns true.
             */
            bool isSequential() const override;

            /**
             * Method you can use to determine the encryption input chunk size.
             *
             * \return Returns the input chunk size.
             */
            virtual unsigned inputChunkSize() const = 0;

            /**
             * Method you can use to determine the encryption output chunk size.  The default implementation will
             * call \ref Crypto::Encryptor::inputChunkSize.
             *
             * \return Returns the encrypted chunk size.
             */
            virtual unsigned outputChunkSize() const;

            /**
             * Method you can use to determine the total number of input bytes that have been processed.
             *
             * \return Returns the total number of processed input bytes.
             */
            unsigned long long numberInputBytesProcessed() const;

            /**
             * Method you can use to determine the total number of output bytes that have been processed.
             *
             * \return Returns the total number of processed output bytes.
             */
            unsigned long long numberOutputBytesProcessed() const;

        protected:
            /**
             * Method that is called to request data from the encryptor.
             *
             * \param[in] data    Pointer to the buffer to receive the requested data.
             *
             * \param[in] maxSize The maximum amount of data to be read.
             *
             * \return Returns the actual amount of data read.  This method always returns a length
             *         of -1, indicating an error condition.
             */
            qint64 readData(char* data, qint64 maxSize) override;

            /**
             * Method that is called to write data.  This method will trigger the encryptor to be run.
             *
             * \param[in] data    The data to be encrypted and written out.
             *
             * \param[in] maxSize The number of available bytes
             *
             * \return Returns the actual number of bytes written.
             */
            qint64 writeData(const char* data, qint64 maxSize) override;

            /**
             * Method that is called to reset the encryption engine.
             */
            virtual void resetEngine() = 0;

            /**
             * Method you should overload to perform encryption on a single chunk.  Data will always be supplied in
             * full chunks.
             *
             * \param[in]  inputData  Pointer to the unencrypted data to be processed.
             *
             * \param[out] outputData Pointer to the buffer to receive the resulting data.
             */
            virtual void encryptChunk(const std::uint8_t* inputData, std::uint8_t* outputData) = 0;

        private:
            /**
             * Method that is called to perform common configuration tasks.
             *
             * \param[in] outputDevice The default output device.
             */
            void configure(QIODevice* outputDevice = Q_NULLPTR);

            /**
             * Pointer to the output device.
             */
            QIODevice* currentOutputDevice;

            /**
             * The input buffer allocation.
             */
            unsigned inputBufferAllocation;

            /**
             * The output buffer allocation.
             */
            unsigned outputBufferAllocation;

            /**
             * The input buffer.
             */
            QByteArray inputBuffer;

            /**
             * The output buffer.
             */
            QByteArray outputBuffer;

            /**
             * The current input buffer index;
             */
            unsigned inputBufferIndex;

            /**
             * Pointer to the input buffer.
             */
            std::uint8_t* inputData;

            /**
             * Value that holds the current number of processed input bytes.
             */
            unsigned long long currentNumberInputBytesProcessed;

            /**
             * Value that holds the current number of processed output bytes.
             */
            unsigned long long currentNumberOutputBytesProcessed;
    };
}

#endif

