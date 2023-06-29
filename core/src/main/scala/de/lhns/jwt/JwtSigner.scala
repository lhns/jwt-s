package de.lhns.jwt

import cats.effect.kernel.Async
import de.lhns.jwt.Jwt.SignedJwt
import de.lhns.jwt.JwtAlgorithm.{JwtAsymmetricAlgorithm, JwtHmacAlgorithm}
import pdi.jwt.JwtUtils

import java.nio.charset.StandardCharsets
import java.security.PrivateKey
import javax.crypto.SecretKey

trait JwtSigner[F[_], -Algorithm <: JwtAlgorithm, Key] {
  def sign(jwt: Jwt, algorithm: Algorithm, key: Key): F[SignedJwt]
}

object JwtSigner {
  implicit def hmacSigner[F[_] : Async]: JwtSigner[F, JwtHmacAlgorithm, SecretKey] = new JwtSigner[F, JwtHmacAlgorithm, SecretKey] {
    override def sign(jwt: Jwt, algorithm: JwtHmacAlgorithm, key: SecretKey): F[SignedJwt] = Async[F].delay {
      val signature = JwtUtils.sign(
        jwt.encode.getBytes(StandardCharsets.UTF_8),
        key,
        algorithm match {
          case JwtAlgorithm.HS256 => pdi.jwt.JwtAlgorithm.HS256
          case JwtAlgorithm.HS384 => pdi.jwt.JwtAlgorithm.HS384
          case JwtAlgorithm.HS512 => pdi.jwt.JwtAlgorithm.HS512
        }
      )
      SignedJwt(jwt, signature)
    }
  }

  implicit def asymmetricSigner[F[_] : Async]: JwtSigner[F, JwtAsymmetricAlgorithm, PrivateKey] = new JwtSigner[F, JwtAsymmetricAlgorithm, PrivateKey] {
    override def sign(jwt: Jwt, algorithm: JwtAsymmetricAlgorithm, key: PrivateKey): F[SignedJwt] = Async[F].delay {
      val signature = JwtUtils.sign(
        jwt.encode.getBytes(StandardCharsets.UTF_8),
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
      SignedJwt(jwt, signature)
    }
  }
}
