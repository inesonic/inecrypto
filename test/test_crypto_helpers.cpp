/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This file implements tests of the Cryptographic helper functions.
***********************************************************************************************************************/

#include <QtGlobal>
#include <QObject>
#include <QtTest/QtTest>
#include <QDateTime>
#include <QTime>
#include <QByteArray>

#include "crypto_helpers.h"

#include "test_crypto_helpers.h"

void TestCryptoHelpers::initTestCase() {
    QTime     time      = QDateTime::currentDateTime().time();
    quint64   julianDay = QDateTime::currentDateTime().date().toJulianDay();
    quint32   mSec      = 1000 * (60 * (60 * time.hour() + time.minute()) + time.second()) + time.msec();
    quint64   seed64    = 86400000ULL * static_cast<quint32>(julianDay) + mSec;

    initializeSeed((seed64 >> 32ULL) + (seed64 & quint32(-1)));
}


void TestCryptoHelpers::testStripByteArray() {
    for (unsigned i=1 ; i<numberIterations ; i++) {
        QByteArray array;

        unsigned startingLength = random32() >> 27;
        int      nonZeroLength  = static_cast<quint64>(random32()) * startingLength / quint32(-1);

        array.clear();
        array.fill(0,startingLength);

        if (nonZeroLength > 0) {
            array[nonZeroLength-1] = 1;
        }

        Crypto::stripByteArray(array);

        QCOMPARE(array.length(), nonZeroLength);
    }
}
