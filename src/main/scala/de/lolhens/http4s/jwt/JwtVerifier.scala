package de.lolhens.http4s.jwt

import java.security.PublicKey

import javax.crypto.SecretKey
import monix.eval.Task
import pdi.jwt.algorithms.{JwtAsymmetricAlgorithm, JwtECDSAAlgorithm, JwtHmacAlgorithm, JwtRSAAlgorithm}
import pdi.jwt.{JwtAlgorithm, JwtUtils}

import scala.util.Try

abstract class JwtVerifier[Algorithm <: JwtAlgorithm, A](val algorithms: Seq[Algorithm]) {
  final def decode(token: String, options: JwtValidationOptions): Task[Try[(Jwt[Algorithm], Option[A])]] = {
    JwtCodec.decodeAllAndVerify(token, options.jwtOptions, {
      case untypedJwt@Jwt(head, claim, _, _) if head.algorithm.forall(algorithms.contains) =>
        val jwt = untypedJwt.asInstanceOf[Jwt[Algorithm]]
        options.validateRequired(claim)
        verified(jwt)

      case _ => Task.now(None)
    }).map(_.map {
      case (jwt, verified) => (jwt.asInstanceOf[Jwt[Algorithm]], verified)
    })
  }

  protected def verified(jwt: Jwt[Algorithm]): Task[Option[A]]

  final protected def verify(jwt: Jwt[Algorithm],
                             key: String): Boolean =
    JwtUtils.verify(jwt.data, jwt.signature, key, jwt.algorithm.get)

  final protected def verifyHmac(jwt: Jwt[_ <: JwtHmacAlgorithm],
                                 key: SecretKey): Boolean =
    JwtUtils.verify(jwt.data, jwt.signature, key, jwt.algorithm.get)

  final protected def verifyAsymmetric(jwt: Jwt[_ <: JwtAsymmetricAlgorithm],
                                       key: PublicKey): Boolean =
    JwtUtils.verify(jwt.data, jwt.signature, key, jwt.algorithm.get)
}

object JwtVerifier {
  val allAlgorithms: Seq[JwtAlgorithm] =
    JwtAlgorithm.allHmac() ++ JwtAlgorithm.allRSA() ++ JwtAlgorithm.allECDSA()

  def apply(key: String,
            algorithms: Seq[JwtAlgorithm] = allAlgorithms): JwtVerifier[JwtAlgorithm, Unit] =
    new JwtVerifier[JwtAlgorithm, Unit](algorithms) {
      override protected def verified(jwt: Jwt[JwtAlgorithm]): Task[Option[Unit]] =
        Task.now(if (verify(jwt, key)) Some(()) else None)
    }

  def hmac(key: SecretKey,
           algorithms: Seq[JwtHmacAlgorithm] = JwtAlgorithm.allHmac()): JwtVerifier[JwtHmacAlgorithm, Unit] =
    new JwtVerifier[JwtHmacAlgorithm, Unit](algorithms) {
      override protected def verified(jwt: Jwt[JwtHmacAlgorithm]): Task[Option[Unit]] =
        Task.now(if (verifyHmac(jwt, key)) Some(()) else None)
    }

  def asymmetric[Algorithm <: JwtAsymmetricAlgorithm](key: PublicKey,
                                                      algorithms: Seq[Algorithm]): JwtVerifier[Algorithm, Unit] =
    new JwtVerifier[Algorithm, Unit](algorithms) {
      override protected def verified(jwt: Jwt[Algorithm]): Task[Option[Unit]] =
        Task.now(if (verifyAsymmetric(jwt, key)) Some(()) else None)
    }

  def asymmetric(key: PublicKey): JwtVerifier[JwtAsymmetricAlgorithm, Unit] =
    asymmetric(key, JwtAlgorithm.allAsymmetric())

  def rsa(key: PublicKey,
          algorithms: Seq[JwtRSAAlgorithm] = JwtAlgorithm.allRSA()): JwtVerifier[JwtRSAAlgorithm, Unit] =
    asymmetric(key, algorithms)

  def ecdsa(key: PublicKey,
            algorithms: Seq[JwtECDSAAlgorithm] = JwtAlgorithm.allECDSA()): JwtVerifier[JwtECDSAAlgorithm, Unit] =
    asymmetric(key, algorithms)
}
