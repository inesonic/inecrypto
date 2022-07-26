/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This header provides abstraction for operating system specific cryptographic libraries.
***********************************************************************************************************************/

/* .. sphinx-project inecrypto */

#ifndef CRYPTO_TRNG_H
#define CRYPTO_TRNG_H

#include <QtGlobal>

namespace Crypto {
    /**
     *
     * Function that returns a random 32-bit value meeting the requirements for a cryptographic system.  The function
     * relies on the APIs of the underlying operating system.
     */
    quint32 random32();

    /**
     *
     * Function that returns a random 64-bit value meeting the requirements for a cryptographic system.  The function
     * relies on the APIs of the underlying operating system.
     */
    quint64 random64();
};

#endif
