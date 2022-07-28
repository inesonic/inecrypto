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
* This file implements the \ref Crypto::Decryptor class.
***********************************************************************************************************************/

#include <QMap>
#include <QIODevice>
#include <QObject>
#include <QString>

#include <cstring>

#include "crypto_decryptor.h"

namespace Crypto {
    Decryptor ::Decryptor(QIODevice* parent):QIODevice(parent) {
        configure(parent);
    }


    Decryptor ::Decryptor(QObject* parent):QIODevice(parent) {
        configure();
    }


    Decryptor::~Decryptor() {}


    QByteArray Decryptor::decrypt(const QByteArray& inputBuffer) {
        unsigned long long  numberInputBytes = static_cast<unsigned long long>(inputBuffer.size());
        const std::uint8_t* inputData        = reinterpret_cast<const std::uint8_t*>(inputBuffer.data());

        unsigned inputBufferAllocation  = inputChunkSize();
        unsigned outputBufferAllocation = outputChunkSize();

        unsigned long long  numberChunks      = numberInputBytes / inputBufferAllocation;
        unsigned long long  numberOutputBytes = numberChunks * outputBufferAllocation;

        QByteArray result(numberOutputBytes, '\x00');

        std::uint8_t*      outputData          = reinterpret_cast<std::uint8_t*>(result.data());
        unsigned long long inputBytesRemaining = numberInputBytes;

        resetEngine();
        while (inputBytesRemaining >= inputBufferAllocation) {
            decryptChunk(inputData, outputData);

            inputData += inputBufferAllocation;
            outputData += outputBufferAllocation;

            inputBytesRemaining -= inputBufferAllocation;
        }

        return result;
    }


    void Decryptor::setInputDevice(QIODevice* inputDevice) {
        if (currentInputDevice != Q_NULLPTR) {
            disconnect(currentInputDevice, &QIODevice::readyRead, this, &Decryptor::inputDataAvailable);
        }

        currentInputDevice = inputDevice;

        if (currentInputDevice != Q_NULLPTR) {
            connect(currentInputDevice, &QIODevice::readyRead, this, &Decryptor::inputDataAvailable);
            if (currentInputDevice->bytesAvailable() > 0) {
                inputDataAvailable();
            }
        }
    }


    QIODevice* Decryptor::inputDevice() const {
        return currentInputDevice;
    }


    unsigned long long Decryptor::inputBytesPending() const {
        return static_cast<unsigned long long>(inputBuffer.size());
    }


    qint64 Decryptor::bytesAvailable() const {
        unsigned long long inputBytesAvailable = static_cast<unsigned long long>(inputBuffer.size());
        if (currentInputDevice != Q_NULLPTR) {
            inputBytesAvailable += currentInputDevice->bytesAvailable();
        }

        unsigned           inChunkSize       = inputChunkSize();
        unsigned           outChunkSize      = outputChunkSize();
        unsigned long long numberInputChunks = inputBytesAvailable / inChunkSize;
        unsigned long long outputBufferBytes = outputBuffer.size() + outChunkSize * numberInputChunks;

        return outputBufferBytes + QIODevice::bytesAvailable();
    }


    bool Decryptor::canReadLine() const {
        return QIODevice::canReadLine() || outputBuffer.contains('\n');
    }


    bool Decryptor::open(Decryptor::OpenMode openMode) {
        bool result;

        if (openMode == OpenModeFlag::ReadOnly) {
            resetEngine();
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


    bool Decryptor::isSequential() const {
        return true;
    }


    unsigned Decryptor::inputChunkSize() const {
        return outputChunkSize();
    }


    unsigned long long Decryptor::numberInputBytesProcessed() const {
        return currentNumberInputBytesProcessed;
    }


    unsigned long long Decryptor::numberOutputBytesProcessed() const {
        return currentNumberOutputBytesProcessed;
    }


    void Decryptor::processData(const QByteArray& data) {
        if (!data.isEmpty()) {
            inputBuffer.append(data);
            emit readyRead();
        }
    }


    qint64 Decryptor::readData(char* data, qint64 maxSize) {
        qint64 result;

        if (!sourceReportedError) {
            unsigned long long bytesRead;
            readAvailableData(bytesRead);

            unsigned long long numberInputBytes  = static_cast<unsigned long long>(inputBuffer.size());
            unsigned           inChunkSize       = inputChunkSize();
            unsigned           outChunkSize      = outputChunkSize();
            unsigned long long numberChunks      = numberInputBytes / inChunkSize;
            unsigned long long numberNewBytes    = numberChunks * outChunkSize;
            unsigned long long currentOutputSize = static_cast<unsigned long long>(outputBuffer.size());

            outputBuffer.resize(numberNewBytes + currentOutputSize);
            std::uint8_t*       d = reinterpret_cast<std::uint8_t*>(outputBuffer.data() + currentOutputSize);
            const std::uint8_t* s = reinterpret_cast<std::uint8_t*>(inputBuffer.data());

            for (unsigned chunk=0 ; chunk<numberChunks ; ++chunk) {
                decryptChunk(s, d);
                s += inChunkSize;
                d += outChunkSize;

                currentNumberInputBytesProcessed  += inChunkSize;
                currentNumberOutputBytesProcessed += outChunkSize;
            }

            result = std::min(maxSize, static_cast<qint64>(outputBuffer.size()));
            std::memcpy(data, outputBuffer.data(), result);

            inputBuffer  = inputBuffer.mid(numberChunks * inChunkSize);
            outputBuffer = outputBuffer.mid(result);
        } else {
            result = -1;
        }

        return result;
    }


    qint64 Decryptor::writeData(const char* /* data */, qint64 /* maxSize */) {
        return -1;
    }


    void Decryptor::inputDataAvailable() {
        unsigned long long bytesRead = 0;
        readAvailableData(bytesRead);

        if (bytesRead > 0) {
            unsigned long long inputBufferSize = static_cast<unsigned long long>(inputBuffer.size());
            if (inputBufferSize >= inputChunkSize()) {
                emit readyRead();
            }
        }
    }


    void Decryptor::configure(QIODevice* inputDevice) {
        currentInputDevice                = inputDevice;
        sourceReportedError               = false;
        currentNumberInputBytesProcessed  = static_cast<unsigned long long>(-1);
        currentNumberOutputBytesProcessed = static_cast<unsigned long long>(-1);
    }


    bool Decryptor::readAvailableData(unsigned long long& bytesRead) {
        bool success = false;

        if (currentInputDevice != Q_NULLPTR) {
            unsigned long long bytesToRead = static_cast<unsigned long long>(currentInputDevice->bytesAvailable());
            if (bytesToRead > 0) {
                unsigned long long receiveBufferSize = static_cast<unsigned long long>(inputBuffer.size());

                inputBuffer.resize(bytesToRead + receiveBufferSize);

                qint64 bytesActuallyRead = currentInputDevice->read(
                    inputBuffer.data() + receiveBufferSize,
                    bytesToRead
                );

                if (bytesActuallyRead != static_cast<qint64>(bytesToRead)) {
                    setErrorString(tr("Data source reported error."));
                    sourceReportedError = true;
                    success             = false;
                    bytesRead           = 0;
                } else {
                    success   = true;
                    bytesRead = bytesToRead;
                }
            } else {
                bytesRead = 0;
            }
        } else {
            bytesRead = 0;
        }

        return success;
    }
}


