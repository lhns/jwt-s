package de.lolhens.http4s.jwt

import de.lolhens.http4s.jwt.JwtValidationOptions._
import pdi.jwt._
import pdi.jwt.exceptions.{JwtExpirationException, JwtNotBeforeException, JwtValidationException}

case class JwtValidationOptions(signature: Boolean = true,
                                validateExpiration: Boolean = true,
                                validateNotBefore: Boolean = true,
                                requireIssuer: Boolean = false,
                                requireSubject: Boolean = false,
                                requireAudience: Boolean = false,
                                requireExpiration: Boolean = false,
                                requireNotBefore: Boolean = false,
                                requireIssuedAt: Boolean = false,
                                requireJwtId: Boolean = false,
                                leeway: Long = 0) {
  private[jwt] val jwtOptions: JwtOptions = JwtOptions(
    signature = signature,
    expiration = validateExpiration,
    notBefore = validateNotBefore,
    leeway = leeway
  )

  private[jwt] def validateRequired(claim: JwtClaim): Unit = {
    if (requireIssuer && claim.issuer.isEmpty) throw new JwtEmptyIssuerException()
    if (requireSubject && claim.subject.isEmpty) throw new JwtEmptySubjectException()
    if (requireAudience && claim.audience.isEmpty) throw new JwtEmptyAudienceException()
    if (requireExpiration && claim.expiration.isEmpty) throw new JwtEmptyExpirationException()
    if (requireNotBefore && claim.notBefore.isEmpty) throw new JwtEmptyNotBeforeException()
    if (requireIssuedAt && claim.issuedAt.isEmpty) throw new JwtEmptyIssuedAtException()
    if (requireJwtId && claim.jwtId.isEmpty) throw new JwtEmptyJwtIdException()
  }
}

object JwtValidationOptions {
  val default: JwtValidationOptions = JwtValidationOptions()

  class JwtEmptyIssuerException extends JwtValidationException("The token does not contain an issuer.")

  class JwtEmptySubjectException extends JwtValidationException("The token does not contain a subject.")

  class JwtEmptyAudienceException extends JwtValidationException("The token does not contain an audience.")

  class JwtEmptyExpirationException extends JwtExpirationException(0) {
    override def getMessage: String = "The token does not contain an expiration."
  }

  class JwtEmptyNotBeforeException extends JwtNotBeforeException(0) {
    override def getMessage: String = "The token does not contain when it will be valid."
  }

  class JwtEmptyIssuedAtException extends JwtValidationException("The token does not contain when it was issued.")

  class JwtEmptyJwtIdException extends JwtValidationException("The token does not contain a jwt id.")

  class JwtUnknownIssuerException extends JwtValidationException("The token does not contain a known issuer.")

}
