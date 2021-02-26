package de.lolhens.http4s.jwt

import cats.Monad
import cats.syntax.functor._
import pdi.jwt.algorithms.{JwtAsymmetricAlgorithm, JwtECDSAAlgorithm, JwtHmacAlgorithm, JwtRSAAlgorithm}
import pdi.jwt.{JwtAlgorithm, JwtUtils}

import java.security.PublicKey
import javax.crypto.SecretKey
import scala.reflect.ClassTag
import scala.util.Try

abstract class JwtVerifier[F[_], Algorithm <: JwtAlgorithm, A](val algorithms: Seq[Algorithm])
                                                              (implicit F: Monad[F]) {
  private implicit val `Jwt[Algorithm]`: ClassTag[Jwt[Algorithm]] = implicitly[ClassTag[Jwt[Algorithm]]]

  final def decode(token: String, options: JwtValidationOptions): F[Try[(Jwt[Algorithm], Option[A])]] = {
    JwtCodec.decodeAllAndVerify[F, A](token, options.jwtOptions, {
      case `Jwt[Algorithm]`(jwt@Jwt(head, claim, _, _)) if head.algorithm.forall(algorithms.contains) =>
        options.validateRequired(claim)
        verified(jwt)

      case _ =>
        F.pure(None)
    }).map(_.map {
      case (`Jwt[Algorithm]`(jwt), verified) =>
        (jwt, verified)
    })
  }

  protected def verified(jwt: Jwt[Algorithm]): F[Option[A]]

  final protected def verify(jwt: Jwt[Algorithm],
                             key: String): Boolean =
    JwtUtils.verify(jwt.data, jwt.signature, key, jwt.algorithm.get)

  final protected def verifyHmac(jwt: Jwt[JwtHmacAlgorithm],
                                 key: SecretKey): Boolean =
    JwtUtils.verify(jwt.data, jwt.signature, key, jwt.algorithm.get)

  final protected def verifyAsymmetric(jwt: Jwt[JwtAsymmetricAlgorithm],
                                       key: PublicKey): Boolean =
    JwtUtils.verify(jwt.data, jwt.signature, key, jwt.algorithm.get)
}

object JwtVerifier {
  val allAlgorithms: Seq[JwtAlgorithm] =
    JwtAlgorithm.allHmac() ++ JwtAlgorithm.allRSA() ++ JwtAlgorithm.allECDSA()

  def apply[F[_]](key: String,
                  algorithms: Seq[JwtAlgorithm] = allAlgorithms)
                 (implicit F: Monad[F]): JwtVerifier[F, JwtAlgorithm, Unit] =
    new JwtVerifier[F, JwtAlgorithm, Unit](algorithms) {
      override protected def verified(jwt: Jwt[JwtAlgorithm]): F[Option[Unit]] =
        F.pure(if (verify(jwt, key)) Some(()) else None)
    }

  def hmac[F[_]](key: SecretKey,
                 algorithms: Seq[JwtHmacAlgorithm] = JwtAlgorithm.allHmac())
                (implicit F: Monad[F]): JwtVerifier[F, JwtHmacAlgorithm, Unit] =
    new JwtVerifier[F, JwtHmacAlgorithm, Unit](algorithms) {
      override protected def verified(jwt: Jwt[JwtHmacAlgorithm]): F[Option[Unit]] =
        F.pure(if (verifyHmac(jwt, key)) Some(()) else None)
    }

  def asymmetric[F[_], Algorithm <: JwtAsymmetricAlgorithm](key: PublicKey,
                                                            algorithms: Seq[Algorithm])
                                                           (implicit F: Monad[F]): JwtVerifier[F, Algorithm, Unit] =
    new JwtVerifier[F, Algorithm, Unit](algorithms) {
      override protected def verified(jwt: Jwt[Algorithm]): F[Option[Unit]] =
        F.pure(if (verifyAsymmetric(jwt, key)) Some(()) else None)
    }

  def asymmetric[F[_]](key: PublicKey)
                      (implicit F: Monad[F]): JwtVerifier[F, JwtAsymmetricAlgorithm, Unit] =
    asymmetric(key, JwtAlgorithm.allAsymmetric())

  def rsa[F[_]](key: PublicKey,
                algorithms: Seq[JwtRSAAlgorithm] = JwtAlgorithm.allRSA())
               (implicit F: Monad[F]): JwtVerifier[F, JwtRSAAlgorithm, Unit] =
    asymmetric(key, algorithms)

  def ecdsa[F[_]](key: PublicKey,
                  algorithms: Seq[JwtECDSAAlgorithm] = JwtAlgorithm.allECDSA())
                 (implicit F: Monad[F]): JwtVerifier[F, JwtECDSAAlgorithm, Unit] =
    asymmetric(key, algorithms)
}
