package de.lolhens.http4s.jwt

import java.security.PublicKey

import javax.crypto.SecretKey
import pdi.jwt.algorithms.{JwtAsymmetricAlgorithm, JwtECDSAAlgorithm, JwtHmacAlgorithm, JwtRSAAlgorithm}
import pdi.jwt.{JwtAlgorithm, JwtUtils}

import scala.util.Try

abstract class JwtVerifier[Algorithm <: JwtAlgorithm, A](val algorithms: Seq[Algorithm]) {
  final def decode(token: String, options: JwtValidationOptions): Try[(Jwt[Algorithm], A)] = {
    JwtCodec.decodeAllAndVerify(token, options.jwtOptions, {
      case untypedJwt@Jwt(algorithm, _, claim, _, _) if algorithms.contains(algorithm) =>
        val jwt = untypedJwt.asInstanceOf[Jwt[Algorithm]]
        options.validateRequired(claim)
        verified(jwt).map((jwt, _))

      case _ =>
        None
    })
  }

  protected def verified(jwt: Jwt[Algorithm]): Option[A]

  final protected def verify(jwt: Jwt[Algorithm], key: String): Boolean =
    JwtUtils.verify(jwt.data, jwt.signature, key, jwt.algorithm)

  final protected def verifyHmac(jwt: Jwt[Algorithm], key: SecretKey)
                                (implicit ev0: Algorithm <:< JwtHmacAlgorithm): Boolean =
    JwtUtils.verify(jwt.data, jwt.signature, key, jwt.algorithm)

  final protected def verifyAsymmetric(jwt: Jwt[Algorithm], key: PublicKey)
                                      (implicit ev0: Algorithm <:< JwtAsymmetricAlgorithm): Boolean =
    JwtUtils.verify(jwt.data, jwt.signature, key, jwt.algorithm)
}

object JwtVerifier {
  val allAlgorithms: Seq[JwtAlgorithm] =
    JwtAlgorithm.allHmac() ++ JwtAlgorithm.allRSA() ++ JwtAlgorithm.allECDSA()

  def apply(key: String,
            algorithms: Seq[JwtAlgorithm] = allAlgorithms): JwtVerifier[JwtAlgorithm, Unit] =
    new JwtVerifier[JwtAlgorithm, Unit](algorithms) {
      override protected def verified(jwt: Jwt[JwtAlgorithm]): Option[Unit] =
        if (verify(jwt, key)) Some(()) else None
    }

  def hmac(key: SecretKey,
           algorithms: Seq[JwtHmacAlgorithm] = JwtAlgorithm.allHmac()): JwtVerifier[JwtHmacAlgorithm, Unit] =
    new JwtVerifier[JwtHmacAlgorithm, Unit](algorithms) {
      override protected def verified(jwt: Jwt[JwtHmacAlgorithm]): Option[Unit] =
        if (verifyHmac(jwt, key)) Some(()) else None
    }

  def asymmetric[Algorithm <: JwtAsymmetricAlgorithm](key: PublicKey,
                                                      algorithms: Seq[Algorithm]): JwtVerifier[Algorithm, Unit] =
    new JwtVerifier[Algorithm, Unit](algorithms) {
      override protected def verified(jwt: Jwt[Algorithm]): Option[Unit] =
        if (verifyAsymmetric(jwt, key)) Some(()) else None
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
