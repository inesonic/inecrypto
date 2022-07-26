/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This header provides tests for the Crypto CRC generator functions.
***********************************************************************************************************************/

#ifndef TEST_CRC_GENERATOR_H
#define TEST_CRC_GENERATOR_H

#include <QObject>
#include <QtTest/QtTest>

class TestCrcGenerator:public QObject {
    Q_OBJECT

    private slots:
        /**
         * Tests the Crypto::systematicCrc template function.
         */
        void testSystematicCrc();

        /**
         * Tests the Crypto::nonSystematicCrcDecode function.
         */
        void testNonSystematicCrcDecode();
};

#endif
