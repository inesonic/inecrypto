/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This header provides tests for the Crypt TRNG functions.
***********************************************************************************************************************/

#ifndef TEST_TRNG_H
#define TEST_TRNG_H

#include <QtGlobal>
#include <QObject>
#include <QVector>
#include <QtTest/QtTest>

class TestTrng:public QObject {
    Q_OBJECT

    public:
        static const unsigned long numberIterations          = 10000;

        #if (defined(Q_OS_WIN))

            /*
             * Windows TRNG is apparently measurably worse than Linux and OS X, at least based on a periodic auto-
             * correlation test.
             */
            static constexpr double maximumAllowedCorrelation = 0.30;
            static constexpr double correlationThreshold = 0.01;

        #else

            static constexpr double maximumAllowedCorrelation = 0.10;
            static constexpr double correlationThreshold = 0.01;

        #endif

        /**
         * Template method that converts a random value of a given type to a value between -1.0 and +1.0
         *
         * \param[in] value The value to convert.
         *
         * \return Returns a value between -1.0 and +1.0
         */
        template<typename T> double uniform(T const value) {
            double f = (1.0*value)/T(-1);
            return 2.0*f - 1.0;
        }

        /**
         * Calculates a periodic auto-correlation for source of random deviates.
         *
         * \param[in] input  Sequence The sequence to calculate the auto-correlation on.
         *
         * \return Returns an array holding the periodic auto-correlation on the sequence.
         */
        QVector<double> periodicAutocorrelation(QVector<double> const& input);

    private slots:
        /**
         * Tests the Crypto::random32 function.
         */
        void testRandom32();

        /**
         * Tests the Crypto::random64 function.
         */
        void testRandom64();
};

#endif
