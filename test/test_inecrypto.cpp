/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This file is the main entry point for the inecrypto unit tests.
***********************************************************************************************************************/

#include <QtTest/QtTest>

#include "test_trng.h"
#include "test_crypto_helpers.h"
#include "test_crc_generator.h"
#include "test_xtea.h"
#include "test_aes_cbc.h"
#include "test_hmac.h"

#define TEST(_X) {                                                  \
    _X _x;                                                          \
    testStatus |= QTest::qExec(&_x, argumentCount, argumentValues); \
}

int main(int argumentCount, char** argumentValues) {
    int testStatus = 0;

    TEST(TestTrng)
    TEST(TestCryptoHelpers)
    TEST(TestCrcGenerator)
    TEST(TestXtea)
    TEST(TestAesCbc)
    TEST(TestHmac)

    return testStatus;
}
