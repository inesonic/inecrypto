/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This header provides tests for the Crypto XTEA encryption/decryption functions.
***********************************************************************************************************************/

#ifndef TEST_XTEA_H
#define TEST_XTEA_H

#include <QtGlobal>
#include <QObject>
#include <QtTest/QtTest>

class TestXtea:public QObject {
    Q_OBJECT

    private slots:
        void testXteaEncryptDecryptBasic();

        void testXteaEncryptDecryptFile();

        void testXteaEncryptDecryptFuzz();

    private:
        static constexpr unsigned N = 100000;
};

#endif
