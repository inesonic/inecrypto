/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This file implements the \ref Crypto::Encryptor class.
***********************************************************************************************************************/

#include <QMap>
#include <QIODevice>
#include <QObject>
#include <QString>

#include <cstring>

#include "crypto_trng.h"
#include "crypto_encryptor.h"

namespace Crypto {
    Encryptor::Encryptor(QIODevice* parent):QIODevice(parent) {
        configure(parent);
    }


    Encryptor::Encryptor(QObject* parent):QIODevice(parent) {
        configure();
    }


    Encryptor::~Encryptor() {}


    QByteArray Encryptor::encrypt(const QByteArray& inputBuffer) {
        unsigned long long  numberInputBytes = static_cast<unsigned long long>(inputBuffer.size());
        const std::uint8_t* inputData        = reinterpret_cast<const std::uint8_t*>(inputBuffer.data());

        unsigned inputBufferAllocation  = inputChunkSize();
        unsigned outputBufferAllocation = outputChunkSize();

        unsigned long long  numberChunks      = (numberInputBytes + inputBufferAllocation - 1) / inputBufferAllocation;
        unsigned long long  numberOutputBytes = numberChunks * outputBufferAllocation;

        QByteArray result(numberOutputBytes, '\x00');

        std::uint8_t*      outputData          = reinterpret_cast<std::uint8_t*>(result.data());
        unsigned long long inputBytesRemaining = numberInputBytes;

        resetEngine();
        while (inputBytesRemaining >= inputBufferAllocation) {
            encryptChunk(inputData, outputData);

            inputData += inputBufferAllocation;
            outputData += outputBufferAllocation;

            inputBytesRemaining -= inputBufferAllocation;
        }

        if (inputBytesRemaining > 0) {
            std::uint8_t* tail = new std::uint8_t[inputBufferAllocation];
            std::memcpy(tail, inputData, inputBytesRemaining);
            unsigned bytesToAppend = inputBufferAllocation - inputBytesRemaining;
            for (unsigned i=0 ; i<bytesToAppend ; ++i) {
                tail[inputBytesRemaining + i] = static_cast<std::uint8_t>(bytesToAppend);
            }

            encryptChunk(tail, outputData);
            delete[] tail;
        }

        return result;
    }


    void Encryptor::setOutputDevice(QIODevice* outputDevice) {
        currentOutputDevice = outputDevice;
    }


    QIODevice* Encryptor::outputDevice() const {
        return currentOutputDevice;
    }


    bool Encryptor::open(Encryptor::OpenMode openMode) {
        bool result;

        if (openMode == OpenModeFlag::WriteOnly || openMode == OpenModeFlag::Append) {
            result = QIODevice::open(openMode);
        } else {
            result = false;
        }

        if (result) {
            currentNumberInputBytesProcessed  = 0;
            currentNumberOutputBytesProcessed = 0;
        }

        return result;
    }


    bool Encryptor::flush() {
        bool success;

        if (currentOutputDevice != Q_NULLPTR) {
            if (inputBufferIndex == 0) {
                success = true;
            } else {
                char bytesRemaining = static_cast<char>(inputBufferAllocation - inputBufferIndex);

                while (inputBufferIndex < inputBufferAllocation) {
                    inputData[inputBufferIndex] = static_cast<char>(bytesRemaining);
                    ++inputBufferIndex;
                }

                encryptChunk(inputData, reinterpret_cast<std::uint8_t*>(outputBuffer.data()));
                inputBufferIndex = 0;

                qint64 bytesWritten = currentOutputDevice->write(outputBuffer);
                success = (bytesWritten == outputBuffer.size());

                if (success) {
                    currentNumberInputBytesProcessed  += bytesRemaining;
                    currentNumberOutputBytesProcessed += bytesWritten;
                }
            }
        } else {
            setErrorString(tr("No output device."));
            success = false;
        }

        return success;
    }


    bool Encryptor::flushAndPad() {
        bool success = flush();

        if (success) {
            std::uint32_t r        = Crypto::random32();
            unsigned      residue  = 3;
            unsigned      padBytes = (r & 0xFF) % outputBufferAllocation;

            r >>= 8;
            for (unsigned i=0 ; i<padBytes ; ++i) {
                if (residue == 0) {
                    r = Crypto::random32();
                    residue = 4;
                }

                std::uint8_t b = static_cast<std::uint8_t>(r & 0xFF);
                r >>= 8;
                --residue;

                outputBuffer[i] = b;
            }

            qint64 bytesWritten = currentOutputDevice->write(outputBuffer.data(), padBytes);
            success = (bytesWritten == padBytes);
            if (!success) {
                setErrorString(tr("Could not write pad: %1").arg(currentOutputDevice->errorString()));
            } else {
                currentNumberOutputBytesProcessed += padBytes;
            }
        }

        return success;
    }


    bool Encryptor::isSequential() const {
        return true;
    }


    unsigned Encryptor::outputChunkSize() const {
        return inputChunkSize();
    }


    unsigned long long Encryptor::numberInputBytesProcessed() const {
        return currentNumberInputBytesProcessed;
    }


    unsigned long long Encryptor::numberOutputBytesProcessed() const {
        return currentNumberOutputBytesProcessed;
    }


    qint64 Encryptor::readData(char* /* data */, qint64 /* maxSize */) {
        return -1;
    }


    qint64 Encryptor::writeData(const char* data, qint64 maxSize) {
        qint64 result = 0;

        if (currentOutputDevice != Q_NULLPTR) {
            if (inputBufferAllocation == 0) {
                inputBufferAllocation  = inputChunkSize();
                outputBufferAllocation = outputChunkSize();

                inputBuffer.resize(inputBufferAllocation);
                outputBuffer.resize(outputBufferAllocation);

                inputBufferIndex = 0;
                inputData = reinterpret_cast<std::uint8_t*>(inputBuffer.data());

                resetEngine();
            }

            unsigned long long  bytesRemaining         = static_cast<unsigned long long>(maxSize);
            const std::uint8_t* source                 = reinterpret_cast<const std::uint8_t*>(data);
            unsigned            bytesRemainingInBuffer = inputBufferAllocation - inputBufferIndex;
            unsigned            bytesToWriteThisPass   = static_cast<unsigned>(
                std::min(static_cast<unsigned long long>(bytesRemainingInBuffer), bytesRemaining)
            );

            std::memcpy(inputData + inputBufferIndex, source, bytesToWriteThisPass);
            inputBufferIndex += bytesToWriteThisPass;

            bool success;
            if (inputBufferIndex >= inputBufferAllocation) {
                encryptChunk(inputData, reinterpret_cast<std::uint8_t*>(outputBuffer.data()));
                qint64 bytesSent = currentOutputDevice->write(outputBuffer);

                if (bytesSent == static_cast<qint64>(outputBufferAllocation)) {
                    result         += bytesToWriteThisPass;
                    source         += bytesToWriteThisPass;
                    bytesRemaining -= bytesToWriteThisPass;

                    currentNumberInputBytesProcessed  += inputBufferAllocation;
                    currentNumberOutputBytesProcessed += outputBufferAllocation;

                    success = true;
                } else {
                    success = false;
                }

                while (success && bytesRemaining >= inputBufferAllocation) {
                    encryptChunk(
                        reinterpret_cast<const std::uint8_t*>(source),
                        reinterpret_cast<std::uint8_t*>(outputBuffer.data())
                    );
                    qint64 bytesSent = currentOutputDevice->write(outputBuffer);

                    if (bytesSent == static_cast<qint64>(outputBufferAllocation)) {
                        result         += inputBufferAllocation;
                        source         += inputBufferAllocation;
                        bytesRemaining -= inputBufferAllocation;

                        currentNumberInputBytesProcessed  += inputBufferAllocation;
                        currentNumberOutputBytesProcessed += outputBufferAllocation;
                    } else {
                        success = false;
                    }
                }

                if (success) {
                    if (bytesRemaining) {
                        std::memcpy(inputData, source, bytesRemaining);
                        inputBufferIndex = bytesRemaining;
                        result += bytesRemaining;
                    } else {
                        inputBufferIndex = 0;
                    }
                } else {
                    setErrorString(tr("Output device reported error: %1").arg(currentOutputDevice->errorString()));
                    result = -1;
                }
            } else {
                result  = bytesToWriteThisPass;
                success = true;
            }
        } else {
            setErrorString(tr("No output device."));
            result = -1;
        }

        return result;
    }


    void Encryptor::configure(QIODevice* outputDevice) {
        currentOutputDevice               = outputDevice;
        inputBufferAllocation             = 0;
        outputBufferAllocation            = 0;
        inputBufferIndex                  = 0;
        inputData                         = Q_NULLPTR;
        currentNumberInputBytesProcessed  = static_cast<unsigned long long>(-1);
        currentNumberOutputBytesProcessed = static_cast<unsigned long long>(-1);
    }
}


