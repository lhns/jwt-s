package de.lhns.jwt

import cats.effect.Async
import de.lhns.jwt.Jwt.SignedJwt
import de.lhns.jwt.JwtAlgorithm.{JwtAsymmetricAlgorithm, JwtHmacAlgorithm}
import pdi.jwt.JwtUtils

import java.nio.charset.StandardCharsets
import java.security.PublicKey
import javax.crypto.SecretKey

trait JwtVerifier[F[_], -Algorithm <: JwtAlgorithm, Key] {
  def verify(signedJwt: SignedJwt, algorithm: Algorithm, key: Key, options: JwtValidationOptions): F[Either[Throwable, Jwt]]
}

object JwtVerifier {
  implicit def hmacVerifier[F[_] : Async]: JwtVerifier[F, JwtHmacAlgorithm, SecretKey] = new JwtVerifier[F, JwtHmacAlgorithm, SecretKey] {
    override def verify(signedJwt: SignedJwt, algorithm: JwtHmacAlgorithm, key: SecretKey, options: JwtValidationOptions): F[Either[Throwable, Jwt]] = Async[F].delay {
      val verified = JwtUtils.verify(
        signedJwt.jwt.encode.getBytes(StandardCharsets.UTF_8),
        signedJwt.signature,
        key,
        algorithm match {
          case JwtAlgorithm.HS256 => pdi.jwt.JwtAlgorithm.HS256
          case JwtAlgorithm.HS384 => pdi.jwt.JwtAlgorithm.HS384
          case JwtAlgorithm.HS512 => pdi.jwt.JwtAlgorithm.HS512
        }
      )
      if (verified) Right(signedJwt.jwt) else Left(new RuntimeException())
    }
  }

  implicit def asymmetricVerifier[F[_] : Async]: JwtVerifier[F, JwtAsymmetricAlgorithm, PublicKey] = new JwtVerifier[F, JwtAsymmetricAlgorithm, PublicKey] {
    override def verify(signedJwt: SignedJwt, algorithm: JwtAsymmetricAlgorithm, key: PublicKey, options: JwtValidationOptions): F[Either[Throwable, Jwt]] = Async[F].delay {
      val verified = JwtUtils.verify(
        signedJwt.jwt.encode.getBytes(StandardCharsets.UTF_8),
        signedJwt.signature,
        key,
        algorithm match {
          case JwtAlgorithm.RS256 => pdi.jwt.JwtAlgorithm.RS256
          case JwtAlgorithm.RS384 => pdi.jwt.JwtAlgorithm.RS384
          case JwtAlgorithm.RS512 => pdi.jwt.JwtAlgorithm.RS512
          case JwtAlgorithm.ES256 => pdi.jwt.JwtAlgorithm.ES256
          case JwtAlgorithm.ES384 => pdi.jwt.JwtAlgorithm.ES384
          case JwtAlgorithm.ES512 => pdi.jwt.JwtAlgorithm.ES512
        }
      )
      if (verified) Right(signedJwt.jwt) else Left(new RuntimeException())
    }
  }
}
