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
* This file implements tests of the Crypto TRNG functions.
***********************************************************************************************************************/

#include <QtGlobal>
#include <QDebug>
#include <QObject>
#include <QtTest/QtTest>

#include <cmath>

#include <crypto_trng.h>
#include "test_trng.h"


QVector<double> TestTrng::periodicAutocorrelation(QVector<double> const& input) {
    unsigned long   length = input.length();
    QVector<double> result(length, 0.0);

    for (unsigned long i=0 ; i<length ; ++i) {
        double x = 0;

        for (unsigned long j=0 ; j<length ; ++j) {
            unsigned long k = (j-i) % length;
            x += input[j]*input[k];
        }

        result[i] = x / length;
    }

    return result;
}


void TestTrng::testRandom32() {
    QVector<double> input;
    for (unsigned long i=0 ; i<numberIterations ; ++i) {
        input.append(uniform(Crypto::random32()));
    }

    QVector<double> result = periodicAutocorrelation(input);

    double averageCorrelation = 0;
    double maximumCorrelation = 0;

    for (long i=1 ; i<result.length() ; ++i) {
        double r = std::fabs(result[i]);
        averageCorrelation += r;
        if (r > maximumCorrelation) {
            maximumCorrelation = r;
        }
    }

    averageCorrelation /= result.length();

    QVERIFY2(averageCorrelation < correlationThreshold, "average correlation");
    QVERIFY2(maximumCorrelation < maximumAllowedCorrelation, "maximum correlation");
}


void TestTrng::testRandom64() {
    QVector<double> input;
    for (unsigned long i=0 ; i<numberIterations ; ++i) {
        input.append(uniform(Crypto::random64()));
    }

    QVector<double> result = periodicAutocorrelation(input);

    double averageCorrelation = 0;
    double maximumCorrelation = 0;

    for (long i=1 ; i<result.length() ; ++i) {
        double r = std::fabs(result[i]);
        averageCorrelation += r;
        if (r > maximumCorrelation) {
            maximumCorrelation = r;
        }
    }

    averageCorrelation /= result.length();

    QVERIFY2(averageCorrelation < correlationThreshold, "average correlation");
    QVERIFY2(maximumCorrelation < maximumAllowedCorrelation, "maximum correlation");
}
