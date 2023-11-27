#include <libqotp/hotp.h>

#include <cmath>

#include <QMessageAuthenticationCode>
#include <QMap>

namespace
{
   /**
    * Decodes a Base32 encoded string to a QByteArray.
    *
    * This function decodes a string encoded in Base32 according to RFC 4648.
    * It supports the standard Base32 alphabet (A-Z2-7) and is case-insensitive.
    *
    * Error handling:
    * - Ignores non-Base32 characters (based on the standard Base32 alphabet).
    * - Handles padding characters ('=') properly.
    * - Returns an empty QByteArray if there are illegal characters or other inconsistencies.
    *
    * @param base32String The Base32 encoded string to decode.
    * @return A QByteArray containing the decoded data, or an empty QByteArray in case of an error.
    */
   QByteArray fromBase32(const QString &base32String)
   {
      static const QMap<char, quint8> base32Alphabet = {
         {'A', 0}   , {'B', 1}  , {'C', 2}  , {'D', 3}   , {'E', 4}  , {'F', 5}  , {'G', 6}  , {'H', 7},
         {'I', 8}   , {'J', 9}  , {'K', 10} , {'L', 11}  , {'M', 12} , {'N', 13} , {'O', 14} ,
         {'P', 15}  , {'Q', 16} , {'R', 17} , {'S', 18}  , {'T', 19} , {'U', 20} , {'V', 21} ,
         {'W', 22}  , {'X', 23} , {'Y', 24} , {'Z', 25}  , {'2', 26} , {'3', 27} , {'4', 28} ,
         {'5', 29}  , {'6', 30} , {'7', 31}
      };

      QByteArray decoded;
      int bitBuffer = 0;
      int currentBits = 0;
      int paddingCount = 0;

      for (QChar c : base32String.toUpper())
      {
         if (c == '=')
         {
            // Padding character
            paddingCount++;
            continue;
         }

         if (!base32Alphabet.contains(c.toLatin1()))
         {
            // Invalid character encountered
            return QByteArray();
         }

         if (paddingCount > 0)
         {
            // Any character after a padding character is invalid
            return QByteArray();
         }

         bitBuffer = (bitBuffer << 5) | base32Alphabet[c.toLatin1()];
         currentBits += 5;

         if (currentBits >= 8)
         {
            decoded.append(static_cast<char>((bitBuffer >> (currentBits - 8)) & 0xFF));
            currentBits -= 8;
         }
      }

      return decoded;
   }
}

// Refer to the detailed documentation in qotp.h for complete information about this function.
QString libqotp::hotp(
    QByteArrayView secret,
    uint64_t counter,
    unsigned int digits,
    unsigned int digitMinimum,
    unsigned int digitMaximum)
{
   // Input validation
   if (secret.isEmpty())
   {
      // An empty secret key is invalid as it compromises the security of the OTP.
      // The shared secret must be kept confidential between the token creator and the token verifier.
      return QString();
   }

   if (digits < digitMinimum || digits > digitMaximum)
   {
      // The RFC 4226 recommends the output OTP to be at least 6 digits long.
      // Digits more than 8 are often not supported by OTP systems and may be harder for users.
      return QString();
   }

   // Counter value to byte array conversion
   QByteArray counterBytes;
   for (int i = 7; i >= 0; --i)
   {
      counterBytes.append((counter >> (i * 8)) & 0xFF);
   }

   // Calculate HMAC-SHA1 hash
   QByteArray hash = QMessageAuthenticationCode::hash(counterBytes, secret, QCryptographicHash::Sha1);

   // Check for valid hash
   if (hash.isEmpty() || hash.length() < 20)
   {
      // An invalid hash indicates an error in the HMAC computation.
      // The length of SHA-1 hash should always be 20 bytes.
      return QString();
   }

   // Dynamic Truncation
   int offset = hash.at(hash.length() - 1) & 0xf;
   if (offset > hash.length() - 4)
   {
      // Ensuring offset is within the bounds of the hash array to prevent out-of-bounds access.
      // The offset calculation is based on the last byte of the hash and must allow for subsequent bytes.
      return QString();
   }

   quint32 truncatedHash = (static_cast<quint32>(hash.at(offset) & 0x7f) << 24) |
                           (static_cast<quint32>(hash.at(offset + 1) & 0xff) << 16) |
                           (static_cast<quint32>(hash.at(offset + 2) & 0xff) << 8) |
                           (static_cast<quint32>(hash.at(offset + 3) & 0xff));

   // Generate HOTP value
   quint32 hotp = truncatedHash % static_cast<quint32>(std::pow(10, digits));

   // Return HOTP as zero-padded string
   return QString::number(hotp).rightJustified(digits, '0');
}

// Refer to the detailed documentation in qotp.h for complete information about this function.
QString libqotp::hotp_base32(
    const QString &base32,
    uint64_t counter,
    unsigned int digits,
    unsigned int digitMinimum,
    unsigned int digitMaximum)
{
   // Decode the Base32 secret
   QByteArray secret = fromBase32(base32);

   // Call the original hotp function with the decoded secret
   return libqotp::hotp(QByteArrayView(secret), counter, digits, digitMinimum, digitMaximum);
}

// Refer to the detailed documentation in qotp.h for complete information about this function.
QString libqotp::hotp_base64(
    const QByteArray &base64,
    uint64_t counter,
    unsigned int digits,
    unsigned int digitMinimum,
    unsigned int digitMaximum,
    QByteArray::Base64Options options)
{
   // Decode the Base32 secret
   QByteArray secret = QByteArray::fromBase64(base64, options);

   // Call the original hotp function with the decoded secret
   return libqotp::hotp(QByteArrayView(secret), counter, digits, digitMinimum, digitMaximum);
}
