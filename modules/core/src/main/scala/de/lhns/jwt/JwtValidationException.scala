package de.lhns.jwt

import java.time.{Instant, ZoneId}

class JwtValidationException(message: String, cause: Throwable) extends RuntimeException(message, cause) {
  def this(message: String) = this(message, null)
}

object JwtValidationException {
  class JwtInvalidAlgorithmException(algorithm: Option[JwtAlgorithm]) extends JwtValidationException(s"The token has an invalid algorithm: ${JwtAlgorithm.toString(algorithm)}")

  class JwtEmptyIssuerException extends JwtValidationException("The token does not contain an issuer.")

  class JwtInvalidIssuerException(issuer: Option[String]) extends JwtValidationException(s"The token has an unexpected issuer: ${issuer.getOrElse("<none>")}")

  class JwtInvalidAudienceException(audiences: Option[Seq[String]]) extends JwtValidationException(s"The token has an unexpected audience: ${audiences.fold("<none>")(_.mkString(", "))}")

  class JwtInvalidTypeException(typ: Option[String]) extends JwtValidationException(s"The token has an unexpected type: ${typ.getOrElse("<none>")}")

  class JwtEmptySubjectException extends JwtValidationException("The token does not contain a subject.")

  class JwtEmptyAudienceException extends JwtValidationException("The token does not contain an audience.")

  class JwtEmptyExpirationException extends JwtValidationException("The token does not contain an expiration.")

  class JwtEmptyNotBeforeException extends JwtValidationException("The token does not contain when it will be valid.")

  class JwtEmptyIssuedAtException extends JwtValidationException("The token does not contain when it was issued.")

  class JwtEmptyJwtIdException extends JwtValidationException("The token does not contain a jwt id.")

  class JwtExpirationException(expiration: Instant) extends JwtValidationException(s"The token is expired since ${expiration.atZone(ZoneId.systemDefault())}")

  class JwtNotBeforeException(notBefore: Instant) extends JwtValidationException(s"The token will only be valid after ${notBefore.atZone(ZoneId.systemDefault())}")

  class JwtInvalidSignatureException(cause: Throwable) extends JwtValidationException("The token signature is not valid.", cause) {
    def this() = this(null)
  }
}
