/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This header provides tests for the Crypto HMAC class.
***********************************************************************************************************************/

#ifndef TEST_HMAC_H
#define TEST_HMAC_H

#include <QtGlobal>
#include <QObject>
#include <QtTest/QtTest>

class TestHmac:public QObject {
    Q_OBJECT

    private slots:
        /**
         * Generates datasets to apply to testHmac().  Ugly name imposed by QtTest.
         */
        void testHmac_data();

        /**
         * Tests the Crypto::Hmac class.
         */
        void testHmac();
};

#endif
