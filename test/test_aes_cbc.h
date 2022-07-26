/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This header provides tests for the Crypto AES(CBC) encryption/decryption functions.
***********************************************************************************************************************/

#ifndef TEST_AES_CBC_H
#define TEST_AES_CBC_H

#include <QtGlobal>
#include <QObject>
#include <QtTest/QtTest>

class TestAesCbc:public QObject {
    Q_OBJECT

    private slots:
        void testAesCbcEncryptDecryptBasic();

        void testAesCbcEncryptDecryptFile();

        void testAesCbcEncryptDecryptFuzz();

    private:
        static constexpr unsigned N = 100000;
};

#endif
