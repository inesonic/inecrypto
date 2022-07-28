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
* This file implements tests of the Crypto CRC generator functions.
***********************************************************************************************************************/

#include <QtGlobal>
#include <QDebug>
#include <QByteArray>
#include <QtTest/QtTest>

#include <crypto_crc_generator.h>

#include "test_crc_generator.h"

void TestCrcGenerator::testSystematicCrc() {
    /* Test Crypto::systematicCrc function
     *
     * Doing math manually:
     *
     * Sending: 01 02 03 04
     * Polynomial: 1D44F (16-bits)
     *
     * In  --- Running CRC ---
     *     MSB             LSB
     *     0000 0000 0000 0000
     * 1   0000 0000 0000 0001
     * 0   0000 0000 0000 0010
     * 0   0000 0000 0000 0100
     * 0   0000 0000 0000 1000
     *
     * 0   0000 0000 0001 0000
     * 0   0000 0000 0010 0000
     * 0   0000 0000 0100 0000
     * 0   0000 0000 1000 0000
     *
     * 0   0000 0001 0000 0000
     * 1   0000 0010 0000 0001
     * 0   0000 0100 0000 0010
     * 0   0000 1000 0000 0100
     *
     * 0   0001 0000 0000 1000
     * 0   0010 0000 0001 0000
     * 0   0100 0000 0010 0000
     * 0   1000 0000 0100 0000
     *
     * 1   1101 0100 1100 1110
     * 1   0111 1101 1101 0010
     * 0   1111 1011 1010 0100
     * 0   0010 0011 0000 0111
     *
     * 0   0100 0110 0000 1110
     * 0   1000 1100 0001 1100
     * 0   1100 1100 0111 0111
     * 0   0100 1100 1010 0001
     *
     * 0   1001 1001 0100 0010
     * 0   1110 0110 1100 1011
     * 1   0001 1001 1101 1000
     * 0   0011 0011 1011 0000
     *
     * 0   0110 0111 0110 0000
     * 0   1100 1110 1100 0000
     * 0   0100 1001 1100 1111
     * 0   1001 0011 1001 1110
     *
     * CRC residue = 0x939E
     */

    QByteArray array("\x01\x02\x03\x04");
    quint16 crc = Crypto::systematicCrc<quint16, 0x1D44F>(array);

    QCOMPARE(crc, quint16(0x939E));
}


void TestCrcGenerator::testNonSystematicCrcDecode() {
    /* Test Crypto::nonSystematicCrcDecode.
     *             MSB      LSB
     * Message:     61 02 44 F1 --> 01100001 00000010 01000100 11110001
     * Polynomial:         1 03 -->                          1 00000011
     *
     *
     * Multiplication:
     *                                01100001000000100100010011110001
     *                                                       100000011
     *                               ----------------------------------
     *
     *                                  0110 0001 0000 0010 0100 0100 1111 0001
     *                                0 1100 0010 0000 0100 1000 1001 1110 0010
     *                        0110 0001 0000 0010 0100 0100 1111 0001 0000 0000
     *                       ------------------------------------------
     *                        0110 0001 1010 0001 0100 0010 0011 1100 0001 0011 -> 0x61A1423C13
     *
     * The division process:
     *
     *                       1100001000000100100010011110001
     *            +------------------------------------------
     *  100000011 | 0110000110100001010000100011110000010011
     *               100000011
     *              -----------
     *                10000101100001010000100011110000010011
     *                100000011
     *               -----------
     *                     100000001010000100011110000010011
     *                     100000011
     *                    -----------
     *                            10010000100011110000010011
     *                            100000011
     *                           -----------
     *                               10001000011110000010011
     *                               100000011
     *                              -----------
     *                                   1001111110000010011
     *                                   100000011
     *                                  -----------
     *                                      1111000000010011
     *                                      100000011
     *                                     -----------
     *                                       111000110010011
     *                                       100000011
     *                                      -----------
     *                                        11000101010011
     *                                        100000011
     *                                       -----------
     *                                         1000100110011
     *                                         100000011
     *                                        -----------
     *                                             100000011
     *                                             100000011
     *                                            -----------
     *                                                     0
     */

    QByteArray ensemble("\x13\x3C\x42\xA1\x61");
    QByteArray expectedResidue;
    QByteArray expectedQuotient("\xF1\x44\x02\x61");
    QByteArray residue;
    QByteArray quotient = Crypto::nonSystematicCrcDecode<0x103>(ensemble, &residue);

    QCOMPARE(residue, expectedResidue);
    QCOMPARE(quotient, expectedQuotient);
}
