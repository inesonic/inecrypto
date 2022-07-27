=========
inecrypto
=========
The inecrypto library provides a small collection of useful cryptographic
functions built on top of Qt 5.  The library exists to extend the native
capabilities of Qt 5.

The library is currently used by **Aion** low-code algorithm development
software and by the now defunct **SpeedSentry** site monitoring
system.  Both products are, or were, supported and sold by
`Inesonic, LLC <https://inesonic.com>`.

The inecrypto library uses code kindly taken from
https://github.com/kokke/tiny-AES-c.  The original source was released
under the unlicense (public domain) terms.


Provided Capabilities
=====================
All functions provided the the inecrypto library are in the ``Crypto``
namespace and include:


+----------------------------+------------------------------------------------+
| Header                     | Description                                    |
+----------------------------+------------------------------------------------+
| crypto_helpers.h           | Header provides the ``Crypto::scrub`` and      |
|                            | ``Crypto::generateRandomArray`` functions you  |
|                            | can use to zero out keys in memory as well as  |
|                            | generate cryptographically secure random       |
|                            | sequences.  The header also includes several   |
|                            | other functions that are used internally.      |
+----------------------------+------------------------------------------------+
| crypto_trng.h              | Header provides the ``Crypto::random32`` and   |
|                            | ``Crypto::random64`` functions that can be     |
|                            | used to generate cryptographically secure      |
|                            | random integers.  Note that the Qt libraries   |
|                            | now include the ``QRandomGenerator::system()`` |
|                            | method which largely obsoletes these           |
|                            | functions.                                     |
+----------------------------+------------------------------------------------+
| crypto_hmac.h              | Header defines the ``Crypto::Hmac`` class you  |
|                            | can use to calculate HMACs given a secret and  |
|                            | ``QByteArray`` payload.                        |
+----------------------------+------------------------------------------------+
| crypto_crc_generator.h     | Header provides the ``Crypto::systematicCrc``  |
|                            | template function.  You can use this function  |
|                            | to calculate systematic CRCs.  Note that the   |
|                            | method is not designed to be fast and was      |
|                            | initially added for internal testing purposes. |
+----------------------------+------------------------------------------------+
| crypto_aes_cbc_encryptor.h | Header provides the                            |
|                            | ``Crypto::AesCbcEncryptor`` class.  You can    |
|                            | use this class to either AES CBC encrypt a     |
|                            | block of data in a ``QByteArray`` or to        |
|                            | encrypt a stream provided by a ``QIODevice``.  |
+----------------------------+------------------------------------------------+
| crypto_aes_cbc_decryptor.h | Header provides the                            |
|                            | ``Crypto::AesCbcDecryptor`` class.  The class  |
|                            | has an API very similar to the                 |
|                            | ``Crypto::AesDbcEncryptor`` class except that  |
|                            | it decrypts rather then encrypts data.         |
+----------------------------+------------------------------------------------+
| crypto_xtea_encryptor.h    | Header provides the ``Crypto::XteaEncryptor``  |
|                            | class.  The class provides an XTEA encryptor   |
|                            | with a CBC-like algorithm.   You can use this  |
|                            | class to either XTEA encrypt a block of data   |
|                            | in a ``QByteArray`` or to encrypt a stream     |
|                            | provided by a ``QIODevice``.                   |
+----------------------------+------------------------------------------------+
| crypto_xtea_decryptor.h    | Header provides the ``Crypto::XteaEncryptor``  |
|                            | class.  The class provides an XTEA encryptor   |
|                            | with a CBC-like algorithm.   You can use this  |
|                            | class to either XTEA encrypt a block of data   |
|                            | in a ``QByteArray`` or to encrypt a stream     |
|                            | provided by a ``QIODevice``.                   |
+----------------------------+------------------------------------------------+

Note that, at this time, Inesonic only uses the ``Crypto::HMAC``,
``Crypto::AesCbc*`` classes as well as the helper functions.  Basic unit tests
are in-place for the other functions but are otherwise only minimally tested.


Building inecrypto
==================
The build environment currently supports both qmake and cmake build tools.  The
build environment includes the following subprojects:

+-----------+-----------------------------------------------------------------+
| Project   | Purpose                                                         |
+===========+=================================================================+
| inecrypto | The inecrypto static library.                                   |
+-----------+-----------------------------------------------------------------+
| test      | An optional QtTest based test framework to validate the         |
|           | inecrypto library functionality.  The test framework will be    |
|           | built automatically by both the qmake and cmake build           |
|           | environment.                                                    |
+-----------+-----------------------------------------------------------------+

Note that the directions below will work for Linux and MacOS.  For Windows,
either use nmake or jom, or with cmake, select a different generator such as
the ninja generator.


Dependencies
------------
The inecrypto library depends on Qt5.  The library has also been lightly tested
against Qt6 under commercial license terms.


qmake
-----
To build inecrypto using qmake:

.. code-block:: bash

   cd inecrypto
   mkdir build
   cd build
   qmake ../inecrypto.pro
   make

If you wish to create a debug build, change the qmake line to:

.. code-block:: bash

   qmake ../inecrypto.pro CONFIG+=debug
   make

Note that the qmake build environment currently does not have an install target
defined.

The qmake build environment will always build a static library.


cmake
-----
To build inecrypto using cmake:

.. code-block:: bash

   cd inecrypto
   mkdir build
   cmake -B. -H.. -DCMAKE_INSTALL_PREFIX=/usr/local/
   make

To install, simply run

.. code-block:: bash

   make install

You can optionally also include ``-Dinecypto_TYPE=SHARED`` or
``-Dinecrypto_TYPE=STATIC`` to specifically build as a shared or static library
respectively.  If not specified, cmake will build a static library.


Licensing
=========
This library is licensed under the MIT license.
