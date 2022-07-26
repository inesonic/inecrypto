/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
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
