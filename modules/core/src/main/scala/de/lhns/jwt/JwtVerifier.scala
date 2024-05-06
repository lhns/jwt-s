package de.lhns.jwt

import cats.Monad
import cats.effect.Clock
import cats.syntax.all._
import de.lhns.jwt.Jwt.JwtPayload
import de.lhns.jwt.JwtValidationException._

import java.time.Instant

trait JwtVerifier[F[_]] {
  def verify(signedJwt: SignedJwt): F[Either[Throwable, Jwt]]
}

object JwtVerifier {
  class DefaultVerifier[F[_] : Monad : Clock](options: JwtValidationOptions) extends JwtVerifier[F] {
    override def verify(signedJwt: SignedJwt): F[Either[Throwable, Jwt]] =
      implicitly[Clock[F]].realTimeInstant
        .map { now =>
          Either.catchOnly[JwtValidationException] {
              validateRequired(signedJwt.payload, options)
              validateTiming(signedJwt.payload, now, options)
            }
            .as(signedJwt.jwt)
        }

    private def validateRequired(payload: JwtPayload, options: JwtValidationOptions): Unit = {
      if (options.requireIssuer && payload.issuer.isEmpty) throw new JwtEmptyIssuerException()
      if (options.requireSubject && payload.subject.isEmpty) throw new JwtEmptySubjectException()
      if (options.requireAudience && payload.audience.isEmpty) throw new JwtEmptyAudienceException()
      if (options.requireExpiration && payload.expiration.isEmpty) throw new JwtEmptyExpirationException()
      if (options.requireNotBefore && payload.notBefore.isEmpty) throw new JwtEmptyNotBeforeException()
      if (options.requireIssuedAt && payload.issuedAt.isEmpty) throw new JwtEmptyIssuedAtException()
      if (options.requireJwtId && payload.jwtId.isEmpty) throw new JwtEmptyJwtIdException()
    }

    private def validateTiming(payload: JwtPayload, now: Instant, options: JwtValidationOptions): Unit = {
      val leewayMillis = options.leeway.toMillis
      payload.expiration
        .filterNot(expiration => now.isBefore(expiration.plusMillis(leewayMillis)))
        .foreach(expiration => throw new JwtExpirationException(expiration))

      payload.notBefore
        .filter(notBefore => now.isAfter(notBefore.minusMillis(leewayMillis)))
        .foreach(notBefore => throw new JwtNotBeforeException(notBefore))
    }
  }
}
