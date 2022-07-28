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
* This header provides a small set of useful functions.
***********************************************************************************************************************/

/* .. sphinx-project inecrypto */

#ifndef CRYPTO_HELPERS_H
#define CRYPTO_HELPERS_H

#include <QtGlobal>
#include <QByteArray>
#include <QString>

#include <cstdint>

namespace Crypto {
    /**
     * Function that scrubs the contents of a byte array.
     *
     * \param[in] array The byte array to be scrubbed.
     */
    void scrub(QByteArray& array);

    /**
     * Function that scrubs the contents of a string.
     *
     * \param[in] str The string to be scrubbed.
     */
    void scrub(QString& str);

    /**
     * Method you can use to generate a byte array holding random data.
     *
     * \param[in] arrayLength The desired array length, in bytes.
     */
    QByteArray generateRandomArray(unsigned arrayLength);

    /**
     * Strip off trailing zeros from a byte array.
     *
     * \param[in] array The array to be stripped.
     *
     * \return Returns a referenced to the stripped array.
     */
    QByteArray& stripByteArray(QByteArray& array);

    /**
     * Function that uses the variable SWAR algorithm to calculate the number of ones in a 64-bit integer value.
     *
     * \param[in] value The value to calculate the number of ones for.
     *
     * \return Returns the computed number of ones.
     */
    unsigned numberOnes64(std::uint64_t value);

    /**
     * Function that calculates MSB location in a 32-bit integer value.
     *
     * \param[in] value The value to calculate the MSB location for.
     *
     * \return Returns the MSB location.  A value of -1 is returned if the supplied value is 0.
     */
    int msbLocation32(std::uint32_t value);

    /**
     * Function that calculates the MSB location in a 64-bit integer value.
     *
     * \param[in] value The value to calculate the MSB location for.
     *
     * \return Returns the MSB location.  A value of -1 is returned if the supplied value is 0.
     */
    int msbLocation64(std::uint64_t value);};
#endif
