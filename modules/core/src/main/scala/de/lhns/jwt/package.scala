package de.lhns

import cats.syntax.all._

import java.util.Base64

package object jwt {
  private[jwt] def decodeBase64(base64: String): Either[IllegalArgumentException, Array[Byte]] =
    Either.catchOnly[IllegalArgumentException](Base64.getDecoder.decode(base64))

  private[jwt] def encodeBase64Padded(bytes: Array[Byte]): String =
    Base64.getEncoder.encodeToString(bytes)

  private[jwt] def decodeBase64Url(base64: String): Either[IllegalArgumentException, Array[Byte]] =
    Either.catchOnly[IllegalArgumentException](Base64.getUrlDecoder.decode(base64))

  private[jwt] def encodeBase64Url(bytes: Array[Byte]): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(bytes)
}
