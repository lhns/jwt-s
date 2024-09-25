package de.lhns.jwt

import cats.data.EitherT
import cats.effect.{Clock, Sync}
import cats.syntax.all._
import cats.{Monad, Monoid}
import de.lhns.jwt.Jwt.{JwtHeader, JwtPayload}
import de.lhns.jwt.JwtValidationException._

import java.time.Instant

sealed trait JwtVerifier[F[_]] {
  def verify(signedJwt: SignedJwt): F[Either[Throwable, Unit]]
}

object JwtVerifier {
  implicit def monoid[F[_] : Monad]: Monoid[JwtVerifier[F]] = new Monoid[JwtVerifier[F]] {
    override def empty: JwtVerifier[F] = new JwtVerifier[F] {
      override def verify(signedJwt: SignedJwt): F[Either[Throwable, Unit]] =
        Monad[F].pure(Right(()))
    }

    override def combine(x: JwtVerifier[F], y: JwtVerifier[F]): JwtVerifier[F] = new JwtVerifier[F] {
      override def verify(signedJwt: SignedJwt): F[Either[Throwable, Unit]] =
        EitherT(x.verify(signedJwt)).flatMapF(_ => y.verify(signedJwt)).value
    }
  }

  def apply[F[_] : Monad](verifier: SignedJwt => F[Either[Throwable, Unit]]): JwtVerifier[F] = new JwtVerifier[F] {
    override def verify(signedJwt: SignedJwt): F[Either[Throwable, Unit]] =
      verifier(signedJwt)
  }

  def delay[F[_] : Sync](verifier: SignedJwt => Either[Throwable, Unit]): JwtVerifier[F] = new JwtVerifier[F] {
    override def verify(signedJwt: SignedJwt): F[Either[Throwable, Unit]] =
      Sync[F].delay(verifier(signedJwt))
  }

  def basicVerifier[F[_] : Monad : Clock](
                                           algorithms: Seq[JwtAlgorithm],
                                           options: JwtValidationOptions = JwtValidationOptions.default
                                         ): JwtVerifier[F] =
    JwtVerifier { signedJwt =>
      implicitly[Clock[F]].realTime.map { now =>
        Either.catchOnly[JwtValidationException] {
          validateRequired(signedJwt.payload, options)
          validateTiming(signedJwt.payload, Instant.ofEpochMilli(now.toMillis), options)
          validateAlgorithm(signedJwt.header, algorithms, options)
        }
      }
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

    if (options.validateExpiration)
      payload.expiration
        .filterNot(expiration => now.isBefore(expiration.plusMillis(leewayMillis))) // fail if current time is not before exp + leeway
        .foreach(expiration => throw new JwtExpirationException(expiration))

    if (options.validateNotBefore)
      payload.notBefore
        .filter(notBefore => now.isBefore(notBefore.minusMillis(leewayMillis))) // fail if current time is before nbf - leeway
        .foreach(notBefore => throw new JwtNotBeforeException(notBefore))
  }

  private def validateAlgorithm(header: JwtHeader, algorithms: Seq[JwtAlgorithm], options: JwtValidationOptions): Unit = {
    def isEmptyAlgorithmValid = !options.requireAlgorithm && header.algorithm.isEmpty

    def isAlgorithmValid = header.algorithm.exists(algorithms.contains)

    if (!(isEmptyAlgorithmValid || isAlgorithmValid))
      throw new JwtInvalidAlgorithmException(header.algorithm)
  }
}
