package de.lhns.jwt

import cats.Monad
import cats.effect.{Clock, Sync}
import de.lhns.jwt.Jwt.JwtPayload
import cats.syntax.all._
import de.lhns.jwt.JwtValidationException._

import java.time.{Instant, ZoneId}

trait JwtVerifier[F[_], -Algorithm <: JwtAlgorithm, Key] {
  def verify(
              signedJwt: SignedJwt,
              algorithm: Algorithm,
              key: Key,
              options: JwtValidationOptions
            )(implicit clock: Clock[F]): F[Either[Throwable, Jwt]]
}

object JwtVerifier {

  abstract class DefaultVerifier[F[_] : Monad, -Algorithm <: JwtAlgorithm, Key] extends JwtVerifier[F, Algorithm, Key] {
    override def verify(
                         signedJwt: SignedJwt,
                         algorithm: Algorithm,
                         key: Key,
                         options: JwtValidationOptions
                       )(implicit clock: Clock[F]): F[Either[Throwable, Jwt]] =
      clock.realTimeInstant
        .map { now =>
          Either.catchOnly[JwtValidationException] {
            validateRequired(signedJwt.payload, options)
            validateTiming(signedJwt.payload, now, options)
          }
        }
        .flatMap(_ =>
          verify(signedJwt, algorithm, key)
        )

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

    def verify(
                signedJwt: SignedJwt,
                algorithm: Algorithm,
                key: Key
              ): F[Either[Throwable, Jwt]]
  }
}
