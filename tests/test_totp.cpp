#include <QtTest>

#include <libqotp/qotp.h>

class test_totp : public QObject
{
   Q_OBJECT

private slots:
   void test_match_rfc_sha1()
   {
      const auto key = QByteArrayView("12345678901234567890");
      QCOMPARE(libqotp::totp(key, 1111111109), QLatin1String("07081804"));
      QCOMPARE(libqotp::totp(key, 1111111111), QLatin1String("14050471"));
      QCOMPARE(libqotp::totp(key, 1234567890), QLatin1String("89005924"));
      QCOMPARE(libqotp::totp(key, 2000000000), QLatin1String("69279037"));
      QCOMPARE(libqotp::totp(key, 20000000000), QLatin1String("65353130"));
   }

   void test_match_rfc_sha1_base32()
   {
      const auto key = QLatin1String("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
      QCOMPARE(libqotp::totp_base32(key, 1111111109), QLatin1String("07081804"));
      QCOMPARE(libqotp::totp_base32(key, 1111111111), QLatin1String("14050471"));
      QCOMPARE(libqotp::totp_base32(key, 1234567890), QLatin1String("89005924"));
      QCOMPARE(libqotp::totp_base32(key, 2000000000), QLatin1String("69279037"));
      QCOMPARE(libqotp::totp_base32(key, 20000000000), QLatin1String("65353130"));
   }

   void test_match_rfc_sha1_base64()
   {
      const auto key = QLatin1String("MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=").toString().toUtf8();;
      QCOMPARE(libqotp::totp_base64(key, 1111111109), QLatin1String("07081804"));
      QCOMPARE(libqotp::totp_base64(key, 1111111111), QLatin1String("14050471"));
      QCOMPARE(libqotp::totp_base64(key, 1234567890), QLatin1String("89005924"));
      QCOMPARE(libqotp::totp_base64(key, 2000000000), QLatin1String("69279037"));
      QCOMPARE(libqotp::totp_base64(key, 20000000000), QLatin1String("65353130"));
   }

   void test_match_rfc_sha256()
   {
      const auto key = QByteArrayView("12345678901234567890123456789012");
      QCOMPARE(libqotp::totp_sha256(key, 1111111109), QLatin1String("68084774"));
      QCOMPARE(libqotp::totp_sha256(key, 1111111111), QLatin1String("67062674"));
      QCOMPARE(libqotp::totp_sha256(key, 1234567890), QLatin1String("91819424"));
      QCOMPARE(libqotp::totp_sha256(key, 2000000000), QLatin1String("90698825"));
      QCOMPARE(libqotp::totp_sha256(key, 20000000000), QLatin1String("77737706"));
   }

   void test_match_rfc_sha256_base32()
   {
      const auto key = QLatin1String("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====");
      QCOMPARE(libqotp::totp_base32_sha256(key, 1111111109), QLatin1String("68084774"));
      QCOMPARE(libqotp::totp_base32_sha256(key, 1111111111), QLatin1String("67062674"));
      QCOMPARE(libqotp::totp_base32_sha256(key, 1234567890), QLatin1String("91819424"));
      QCOMPARE(libqotp::totp_base32_sha256(key, 2000000000), QLatin1String("90698825"));
      QCOMPARE(libqotp::totp_base32_sha256(key, 20000000000), QLatin1String("77737706"));
   }

   void test_match_rfc_sha256_base64()
   {
      const auto key = QLatin1String("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=").toString().toUtf8();;
      QCOMPARE(libqotp::totp_base64_sha256(key, 1111111109), QLatin1String("68084774"));
      QCOMPARE(libqotp::totp_base64_sha256(key, 1111111111), QLatin1String("67062674"));
      QCOMPARE(libqotp::totp_base64_sha256(key, 1234567890), QLatin1String("91819424"));
      QCOMPARE(libqotp::totp_base64_sha256(key, 2000000000), QLatin1String("90698825"));
      QCOMPARE(libqotp::totp_base64_sha256(key, 20000000000), QLatin1String("77737706"));
   }

   void test_match_rfc_sha512()
   {
      const auto key = QByteArrayView("1234567890123456789012345678901234567890123456789012345678901234");
      QCOMPARE(libqotp::totp_sha512(key, 1111111109), QLatin1String("25091201"));
      QCOMPARE(libqotp::totp_sha512(key, 1111111111), QLatin1String("99943326"));
      QCOMPARE(libqotp::totp_sha512(key, 1234567890), QLatin1String("93441116"));
      QCOMPARE(libqotp::totp_sha512(key, 2000000000), QLatin1String("38618901"));
      QCOMPARE(libqotp::totp_sha512(key, 20000000000), QLatin1String("47863826"));
   }

   void test_match_rfc_sha512_base32()
   {
      const auto key = QLatin1String("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=");
      QCOMPARE(libqotp::totp_base32_sha512(key, 1111111109), QLatin1String("25091201"));
      QCOMPARE(libqotp::totp_base32_sha512(key, 1111111111), QLatin1String("99943326"));
      QCOMPARE(libqotp::totp_base32_sha512(key, 1234567890), QLatin1String("93441116"));
      QCOMPARE(libqotp::totp_base32_sha512(key, 2000000000), QLatin1String("38618901"));
      QCOMPARE(libqotp::totp_base32_sha512(key, 20000000000), QLatin1String("47863826"));
   }

   void test_match_rfc_sha512_base64()
   {
      const auto key = QLatin1String("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==").toString().toUtf8();
      QCOMPARE(libqotp::totp_base64_sha512(key, 1111111109), QLatin1String("25091201"));
      QCOMPARE(libqotp::totp_base64_sha512(key, 1111111111), QLatin1String("99943326"));
      QCOMPARE(libqotp::totp_base64_sha512(key, 1234567890), QLatin1String("93441116"));
      QCOMPARE(libqotp::totp_base64_sha512(key, 2000000000), QLatin1String("38618901"));
      QCOMPARE(libqotp::totp_base64_sha512(key, 20000000000), QLatin1String("47863826"));
   }
};

QTEST_MAIN(test_totp)

#include "test_totp.moc"
