/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
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
