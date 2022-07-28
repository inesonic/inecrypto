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
* This file implements a small collection of true random number functions.
***********************************************************************************************************************/

#include <QtGlobal>
#include <QDebug>

#if (defined(Q_OS_DARWIN) || defined(Q_OS_LINUX))

    #include <cstdio>

#else

    #include <Windows.h>
    #include <Wincrypt.h>

#endif

#include "crypto_trng.h"

#if (defined(Q_OS_DARWIN) || defined(Q_OS_LINUX))

    quint32 Crypto::random32() {
        FILE* f = std::fopen("/dev/urandom", "rb");
        Q_ASSERT(f != NULL);

        union {
            quint32 value;
            quint8  array[4];
        } u;

        int count = std::fread(u.array, 1, 4, f);
        Q_ASSERT(count == 4);

        int exitCode = fclose(f);
        Q_ASSERT(exitCode == 0);

        /* If we were concerned about protecting this value, we would wipe out the contents of the array */
        return u.value;
    }


    quint64 Crypto::random64() {
        FILE* f = std::fopen("/dev/urandom", "rb");
        Q_ASSERT(f != NULL);

        union {
            quint64 value;
            quint8  array[8];
        } u;

        int count = std::fread(u.array, 1, 8, f);
        Q_ASSERT(count == 8);

        int exitCode = fclose(f);
        Q_ASSERT(exitCode == 0);

        /* If we were concerned about protecting this value, we would wipe out the contents of the array */
        return u.value;
    }

#elif (defined(Q_OS_WIN)) // Assume Windows,

    quint32 Crypto::random32() {
        HCRYPTPROV cryptoProvider = 0;
        BOOL       ok             = true;

        union {
            quint32 value;
            BYTE    array[4];
        } u;

        ok = CryptAcquireContext(&cryptoProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        if (!ok) {
            if (GetLastError() == NTE_BAD_KEYSET) {
                ok = CryptAcquireContext(&cryptoProvider, nullptr, nullptr, PROV_RSA_FULL, CRYPT_NEWKEYSET);
            }
        }

        if (!ok) {
            qDebug() << "CryptAcquireContext failed " << GetLastError();
            Q_ASSERT(false);
        }

        ok = CryptGenRandom(cryptoProvider, 4, u.array);
        Q_ASSERT(ok);

        /* If we were concerned about protecting this value, we would wipe out the contents of the array */

        ok = CryptReleaseContext(cryptoProvider, 0);
        Q_ASSERT(ok);

        return u.value;
    }


    quint64 Crypto::random64() {
        return static_cast<quint64>(Crypto::random32()) << 32 | static_cast<quint64>(Crypto::random32());
    }

#else

    #error Unknown platform

#endif
