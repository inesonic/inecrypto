/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This header defines the \ref Crypto::Decryptor class.
***********************************************************************************************************************/

/* .. sphinx-project inecrypto */

#ifndef CRYPTO_DECRYPTOR_H
#define CRYPTO_DECRYPTOR_H

#include <QtGlobal>
#include <QIODevice>
#include <QByteArray>
#include <QObject>

#include <cstdint>

#include "crypto_cipher_base.h"

class QObject;

namespace Crypto {
    /**
     * Common base class for decryption engines.  This class provides an API that allows both in-place decryption of
     * a block as well as a QIODevice compatible streaming API.  You can not use both API's simulteanously on the
     * same class instance.
     *
     * Derived classes can use this base class to simplify implementing decryption engines.
     */
    class Decryptor :public QIODevice, public CipherBase {
        public:
            /**
             * Constructor
             *
             * \param[in] parent Pointer to the parent object.  This device will also be used as the input device.
             */
            explicit Decryptor (QIODevice* parent = Q_NULLPTR);

            /**
             * Constructor
             *
             * \param[in] parent Pointer to the parent object.
             */
            explicit Decryptor (QObject* parent = Q_NULLPTR);

            ~Decryptor () override;

            /**
             * Method you can call to perform in-place decryption of a data buffer.
             *
             * \param[in] inputBuffer The buffer to be encrypted.
             *
             * \return Returns an encrypted version of the supplied buffer.
             */
            QByteArray decrypt(const QByteArray& inputBuffer);

            /**
             * Method you can use to set the source device.
             *
             * \param[in] inputDevice The device to monitor to receive the decrypted stream.  This class does
             *                        not take ownership of the input device.
             */
            void setInputDevice(QIODevice* inputDevice);

            /**
             * Method you can use to determine the current input device.
             *
             * \return Returns a pointer to the input device.
             */
            QIODevice* inputDevice() const;

            /**
             * Method that determines the number of input bytes still to be processed.
             *
             * \return Returns the number of input bytes still to be processed.
             */
            unsigned long long inputBytesPending() const;

            /**
             * Method that determines the number of bytes of data that can be read.
             *
             * \return Returns the number of avaiable bytes.
             */
            qint64 bytesAvailable() const override;

            /**
             * Method that determines if an entire line of data can be read.
             *
             * \return Returns true if an entire line can be read.  Returns false if there is no newline in the
             *         current input buffer.
             */
            bool canReadLine() const override;

            /**
             * Method you can use to open up a new file for reading.
             *
             * \param[in] openMode The file open mode.  This method will return false if this value is not a readable
             *                     mode.
             *
             * \return Returns true on success, returns false on error.
             */
            bool open(Decryptor ::OpenMode openMode) override;

            /**
             * Method you can use to determine if this is a sequential device.
             *
             * \return Returns true if this is a sequential device.  Returns false if this is not a sequential device.
             *         this method always returns true.
             */
            bool isSequential() const override;

            /**
             * Method you can use to determine the encryption output chunk size.
             *
             * \return Returns the decrypted chunk size.
             */
            virtual unsigned outputChunkSize() const = 0;

            /**
             * Method you can use to determine the encryption input chunk size.  The default implementation will
             * call the \ref Crypto::Decryptor::outputChunkSize method.
             *
             * \return Returns the encrypted chunk size.
             */
            virtual unsigned inputChunkSize() const;

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

            /**
             * Method you can call to manually stream data into the decryptor.
             *
             * \param[in] data The data to be processed.
             */
            void processData(const QByteArray& data);

        protected:
            /**
             * Method that is called to request data from the decryptor.
             *
             * \param[in] data    Pointer to the buffer to receive the requested data.
             *
             * \param[in] maxSize The maximum amount of data to be read.
             *
             * \return Returns the actual amount of data read.
             */
            qint64 readData(char* data, qint64 maxSize) override;

            /**
             * Method that is called to write data.
             *
             * \param[in] data    The data to be encrypted and written out.
             *
             * \param[in] maxSize The number of available bytes
             *
             * \return Returns the actual number of bytes written.  This method will always return -1.
             */
            qint64 writeData(const char* data, qint64 maxSize) override;

            /**
             * Method that is called to reset the decryption engine.
             */
            virtual void resetEngine() = 0;

            /**
             * Method you should overload to perform encryption on a single chunk.  Data will always be supplied in
             * full chunks.
             *
             * \param[in]  inputData  Pointer to the encrypted data to be processed.
             *
             * \param[out] outputData Pointer to the buffer to receive the resulting data.
             */
            virtual void decryptChunk(const std::uint8_t* inputData, std::uint8_t* outputData) = 0;

        private slots:
            /**
             * Slot that is triggered when the input device has data available.
             */
            void inputDataAvailable();

        private:
            /**
             * Method that is called to perform common configuration tasks.
             *
             * \param[in] inputDevice The default input device.
             */
            void configure(QIODevice* inputDevice = Q_NULLPTR);

            /**
             * Method that reads the available data.
             *
             * \param[out] bytesRead Returns the number of bytes read.
             *
             * \return Returns true on success, returns false if an error occurs.
             */
            bool readAvailableData(unsigned long long& bytesRead);

            /**
             * Pointer to the input device.
             */
            QIODevice* currentInputDevice;

            /**
             * The input buffer.
             */
            QByteArray inputBuffer;

            /**
             * The output buffer.
             */
            QByteArray outputBuffer;

            /**
             * Flag that is set if a source read error is detected.
             */
            bool sourceReportedError;

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

