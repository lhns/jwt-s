package de.lhns.jwt

import cats.Monad
import cats.effect.{Clock, Sync}
import de.lhns.jwt.Jwt.JwtPayload
import cats.syntax.all._

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

  import DefaultVerifier._

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

  object DefaultVerifier {
    class JwtValidationException(message: String) extends RuntimeException(message)

    class JwtEmptyIssuerException extends JwtValidationException("The token does not contain an issuer.")

    class JwtEmptySubjectException extends JwtValidationException("The token does not contain a subject.")

    class JwtEmptyAudienceException extends JwtValidationException("The token does not contain an audience.")

    class JwtEmptyExpirationException extends JwtValidationException("The token does not contain an expiration.")

    class JwtEmptyNotBeforeException extends JwtValidationException("The token does not contain when it will be valid.")

    class JwtEmptyIssuedAtException extends JwtValidationException("The token does not contain when it was issued.")

    class JwtEmptyJwtIdException extends JwtValidationException("The token does not contain a jwt id.")

    class JwtExpirationException(expiration: Instant) extends JwtValidationException(s"The token is expired since ${expiration.atZone(ZoneId.systemDefault())}")

    class JwtNotBeforeException(notBefore: Instant) extends JwtValidationException(s"The token will only be valid after ${notBefore.atZone(ZoneId.systemDefault())}")
  }
}
