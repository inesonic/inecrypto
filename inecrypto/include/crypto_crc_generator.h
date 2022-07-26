/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This header provides a basic CRC calculation routine.
***********************************************************************************************************************/

/* .. sphinx-project inecrypto */

#ifndef CRYPTO_CRC_GENERATOR_H
#define CRYPTO_CRC_GENERATOR_H

#include <QtGlobal>
#include <QByteArray>
#include <QtMath>
#include <QDebug>

#include "crypto_helpers.h"

namespace Crypto {
    /**
     * Template function that calculates a systematic CRC by shifting.  While slow, the routine can operate with any
     * polynomial.  Note that this routine can be made much faster using table based CRC calculation methods which
     * requires one or more tables to be generated for each CRC polynomial.
     *
     * Template parameters are:
     *   T -          The desired type of the result.  This type should be unsigned.
     *
     *   polynomial - The CRC polynomial represented as an integer value.  The value should be larger than the value
     *                that can be held in the BaseName type by a single bit.  For example, if BaseName is set to
     *                quint32, then a valid CRC might be 0x123456789.
     *
     * \param[in] array The array to calculate the CRC over.
     */
    template<typename T, quint64 polynomial> T systematicCrc(QByteArray const& array) {
        Q_ASSERT(T(-1) > 0);                                                                   // Validates type.
        Q_ASSERT(sizeof(T) == 8 || T(-1) < polynomial);                                        // Validates the CRC.
        Q_ASSERT(sizeof(T) == 8 || ((static_cast<quint64>(T(-1)) << 1ULL) | 1) >= polynomial); // Validates the CRC.

        unsigned crcLength = numberOnes64(T(-1));
        T        crcMask   = T(1) << (crcLength-1);
        T        crc       = 0;

        for (auto it=array.begin(), end=array.end() ; it!=end ; ++it) {
            quint8 value = *it;

            for (unsigned bit=0 ; bit<8 ; ++bit) {
                T msb = crc & crcMask;

                crc = (crc << 1) | (value & 1);
                if (msb) {
                    crc ^= polynomial;
                }

                value >>= 1;
            }
        }

        return crc;
    }

    /**
     * Function that recovers the message from a non-systematic CRC.  The function is designed to be generic, supporting
     * arbitrary polynomials up-to order 55.  Faster implementations are certainly possible.
     *
     * \param[in]  ensemble The message encoded with the CRC.
     *
     * \param[out] residue  The residue from the encrypted CRC.  If the encoded message is correct, the residue will be
     *                      zero which will be indicated by this method returning a zero length value.
     */
    template<quint64 polynomial> QByteArray nonSystematicCrcDecode(
            QByteArray const& ensemble,
            QByteArray*       residue = Q_NULLPTR
        ) {
        QByteArray remainder = ensemble;
        Crypto::stripByteArray(remainder);

        unsigned lastIndex      = remainder.length() - 1;
        unsigned dividendOrder  = 8 * lastIndex + msbLocation32(static_cast<quint8>(remainder[lastIndex]));
        unsigned remainderOrder = dividendOrder;
        unsigned divisorOrder   = msbLocation64(polynomial);

        QByteArray quotient(ensemble.length(), 0);

        if (dividendOrder >= divisorOrder) {
            while (remainderOrder >= divisorOrder) {
                unsigned shiftAmount   = remainderOrder - divisorOrder;
                unsigned shiftByte     = shiftAmount / 8;
                unsigned shiftBit      = shiftAmount % 8;

                quint8 q = quotient.at(shiftByte) | (1 << shiftBit);
                quotient[shiftByte] = q;

                unsigned remainderByte = remainderOrder / 8;
                quint64  mask          = polynomial << shiftBit;
                unsigned maskMsb       = (divisorOrder + shiftBit) / 8;
                int      maskShift     = 8*maskMsb;

                do {
                    quint8 r = static_cast<quint8>(remainder.at(remainderByte)) ^ (mask >> maskShift);
                    remainder[remainderByte] = static_cast<char>(r);

                    maskShift -= 8;
                    --remainderByte;
                } while (maskShift >= 0);

                Crypto::stripByteArray(remainder);

                unsigned remainderLength = remainder.length();
                if (remainderLength == 0) {
                    remainderOrder = 0;
                } else {
                    lastIndex = remainderLength - 1;
                    remainderOrder = 8 * lastIndex + msbLocation32(static_cast<quint8>(remainder.at(lastIndex)));
                }
            }
        }

        Crypto::stripByteArray(quotient);

        if (residue != Q_NULLPTR) {
            *residue = remainder;
        }

        return quotient;
    }
};

#endif
