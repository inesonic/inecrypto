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
* This header provides tests for the Crypto helper functions.
***********************************************************************************************************************/

#ifndef TEST_CRYPTO_HELPERS_H
#define TEST_CRYPTO_HELPERS_H

#include <QtGlobal>
#include <QObject>
#include <QtTest/QtTest>

class TestCryptoHelpers:public QObject {
    Q_OBJECT

    private:
        static const unsigned numberIterations = 100000;

        inline void initializeSeed(quint32 const newSeed) {
            seed = newSeed;
        }

        inline quint32 random32() {
            /* Knuth-Lewis PRNG */

            seed = 1664525 * seed + 1013904223;
            return seed;
        }

        inline quint64 random64() {
            return (static_cast<quint64>(random32()) << 32ULL) | random32();
        }

        quint32 seed;

    private slots:
        /**
         * Initializes the tests.
         */
        void initTestCase();

        /**
         * Tests the Crypto::stripByteArray function.
         */
        void testStripByteArray();
};

#endif
