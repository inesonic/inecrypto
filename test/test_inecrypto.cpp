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
