/*-*-c++-*-*************************************************************************************************************
* Copyright 2016 Inesonic, LLC.
* All rights reserved.
********************************************************************************************************************//**
* \file
*
* This header provides support for an HMAC using several hashes.
***********************************************************************************************************************/

/* .. sphinx-project inecrypto */

#ifndef CRYPTO_HMAC_H
#define CRYPTO_HMAC_H

#include <QtGlobal>
#include <QByteArray>
#include <QCryptographicHash>

namespace Crypto {
    /** \rst:leading-asterisk
     *
     * Class that can be used to perform an RFC-2104 compliant HMAC.  The hash is calculated when the result is
     * requested.  Note that all internal data structures are cleared when the class is destroyed.
     *
     * Typical use of this class is shown in listing :num:`crypo-hmac-example-listing-1` below.
     *
     * .. _crypo-hmac-example-listing-1:
     * .. code-block:: c++
     *    :caption: Example use of the ``Crypto::Hmac`` module
     *
     *    QByteArray key = userKey.toUtf8();
     *    Crypto::Hmac hmac(key, Crypto::Hmac::Sha512);
     *
     *    . . . .
     *
     *    hmac.addData(receivedData);
     *
     *    . . . .
     *
     *    QByteArray hmac = hmac.digest();
     *
     * You can alternately simply pass data in the constructor and calculate a digest immediately as shown in listing
     * :num:`crypo-hmac-example-listing-2`.
     *
     * .. _crypo-hmac-example-listing-2:
     * .. code-block:: c++
     *    :caption: Another example use of the ``Crypto::Hmac`` module
     *
     *    QByteArray key = userKey.toUtf8();
     *    QByteArray hmac = Crypto::Hmac hmac(key, Crypto::Hmac::Sha512).digest();
     *
     * There is currently a bug in this module.  The HMAC is not calculated correctly for keys > the hash block size.
     * At this point there are no cases where this will occur in the code.  Note that an assert has been temporarily
     * added to trap this case, should it occur.
     *
     * \endrst
     */
    class Hmac {
        public:
            /**
             * Supported hashing algorithms.
             */
            enum Algorithm {
                /** Use MD4 hash. */
                Md4 = QCryptographicHash::Md4,

                /** Use MD5 hash. */
                Md5 = QCryptographicHash::Md5,

                /** Use SHA-1 hash. */
                Sha1 = QCryptographicHash::Sha1,

                /** Use SHA-2 with 224 bit digest. */
                Sha224 = QCryptographicHash::Sha224,

                /** Use SHA-2 with 256 bit digest. */
                Sha256 = QCryptographicHash::Sha256,

                /** Use SHA-2 with 384 bit digest. */
                Sha384 = QCryptographicHash::Sha384,

                /** Use SHA-2 with 384 bit digest. */
                Sha512 = QCryptographicHash::Sha512,

                /** Use SHA-3 with 224 bit digest. */
                Sha3_224 = QCryptographicHash::Sha3_224,

                /** Use SHA-3 with 256 bit digest. */
                Sha3_256 = QCryptographicHash::Sha3_256,

                /** Use SHA-3 with 384 bit digest. */
                Sha3_384 = QCryptographicHash::Sha3_384,

                /** Use SHA-3 with 512 bit digest. */
                Sha3_512 = QCryptographicHash::Sha3_512
            };

            /**
             * Constructor.
             *
             * \param[in] newKey       The user's key.
             *
             * \param[in] newAlgorithm The algorithm to be applied.
             */
            Hmac(
                QByteArray const&             newKey,
                Crypto::Hmac::Algorithm const newAlgorithm = Crypto::Hmac::Algorithm::Sha256
            );

            /**
             * Constructor.
             *
             * \param[in] key       The user's key.
             *
             * \param[in] data      The new starting data.
             *
             * \param[in] algorithm The algorithm to be applied.
             */
            Hmac(
                QByteArray const&             key,
                QByteArray const&             data,
                Crypto::Hmac::Algorithm const algorithm = Crypto::Hmac::Algorithm::Sha256);

            ~Hmac();

            /**
             * Adds data to the hash.
             *
             * \param[in] newData    The data to be added.
             *
             * \param[in] dataLength The number of bytes of data.
             */
            inline void addData(char const* newData, int const dataLength) {
                inner.addData(newData, dataLength);
            }

            /**
             * Adds data to the hash.
             *
             * \param[in] newData    The data to be added.
             *
             * \param[in] dataLength The number of bytes of data.
             */
            inline void addData(unsigned char const* newData, int const dataLength) {
                addData(reinterpret_cast<char const*>(newData), dataLength);
            }

            /**
             * Adds data to the hash.
             *
             * \param[in] newData The data to be added.
             */
            inline void addData(QByteArray const& newData) {
                inner.addData(newData);
            }

            /**
             * Resets all internally stored data.
             *
             * Note that the key is maintained.
             */
            void reset();

            /**
             * Resets all internally stored data, assigning a new key.
             *
             * \param[in] newKey The new key for the HMAC.
             */
            void reset(QByteArray const& newKey);

            /**
             * Calculates the HMAC and returns the result.  Note that once the digest is calculated, the class must be
             * reset before it can be used further.
             *
             * \return Returns an array of bytes containing the calculated HMAC.
             */
            QByteArray digest();

            /**
             * Determines the block size for various hashing algorithms.
             *
             * \param[in] algorithm The algorithm in question.
             *
             * \return Returns the block size in bytes.
             */
            static unsigned blockSize(Hmac::Algorithm const algorithm);

            /**
             * Determines the digest size for various hashing algorithms.
             *
             * \param[in] algorithm The algorithm in question.
             *
             * \return Returns the digest size in bytes.
             */
            static unsigned digestSize(Hmac::Algorithm const algorithm);

        private:
            QByteArray xorArray(QByteArray const& data, quint8 const value);
            QByteArray generatePaddedKey(QByteArray const& key);
            void       initialize(QByteArray const& newKey, Crypto::Hmac::Algorithm const newAlgorithm);
            void       zeroArray(QByteArray& array);

            static unsigned const minimumBlockSize = 16;
            static unsigned const forcedBlockSize  = 64;

            bool                    instanceSpent;
            Crypto::Hmac::Algorithm currentAlgorithm;
            QByteArray              paddedKey;
            QCryptographicHash      inner;
            QCryptographicHash      outer;
    };
};
#endif
