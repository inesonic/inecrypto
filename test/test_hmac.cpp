/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This file implements tests of the Crypto HMAC class.
***********************************************************************************************************************/

#include <QDebug>
#include <QString>
#include <QByteArray>
#include <QtTest/QtTest>

#include <crypto_hmac.h>

#include "test_hmac.h"

void TestHmac::testHmac_data() {
    /* Build matrix. */
    QTest::addColumn<QString>("keyString");
    QTest::addColumn<QString>("dataString");
    QTest::addColumn<QString>("digestString");

    /* Test Values */
    QTest::newRow("small key")
        << "6B6579" << "64617461"
        << "5031FE3D989C6D1537A013FA6E739DA23463FDAEC3B70137D828E36ACE221BD0";

    QTest::newRow("64-byte key")
        << "3031323334353637383941424344454630313233343536373839414243444546"
           "3031323334353637383941424344454630313233343536373839414243444546" << "64617461"
        << "A5218D988FD61090F48EDD4432333355B0D11465FBDE58F558869EC0037AC907";

//    QTest::newRow("70-byte key")
//        << "3031323334353637383941424344454630313233343536373839414243444546"
//           "3031323334353637383941424344454630313233343536373839414243444546"
//           "353433323130" << "6D6F72652064617461"
//        << "65116C2E4C618A166D2B633E87FBEE279F4AD5956E0B362EBCD763A038BD3654";
}

void TestHmac::testHmac() {
    QFETCH(QString,keyString);
    QFETCH(QString,dataString);
    QFETCH(QString,digestString);

    QByteArray key = QByteArray::fromHex(keyString.toUtf8());
    QByteArray data = QByteArray::fromHex(dataString.toUtf8());
    QByteArray expectedDigest = QByteArray::fromHex(digestString.toUtf8());

    Crypto::Hmac hmac(key, data);
    QByteArray digest = hmac.digest();

    QCOMPARE(digest, expectedDigest);
}
