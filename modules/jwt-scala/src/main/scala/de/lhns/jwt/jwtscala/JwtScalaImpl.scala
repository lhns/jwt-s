package de.lhns.jwt.jwtscala

import cats.effect.Sync
import de.lhns.jwt.JwtAlgorithm.{ES256, ES384, ES512, HS256, HS384, HS512, JwtAsymmetricAlgorithm, JwtHmacAlgorithm, RS256, RS384, RS512}
import de.lhns.jwt.JwtValidationException.JwtInvalidSignatureException
import de.lhns.jwt.{Jwt, JwtAlgorithm, JwtSigner, JwtValidationException, JwtVerifier, SignedJwt}
import de.lhns.jwt.JwtVerifier.DefaultVerifier
import pdi.jwt.JwtUtils

import java.nio.charset.StandardCharsets
import java.security.{PrivateKey, PublicKey}
import javax.crypto.SecretKey

object JwtScalaImpl {
  implicit def hmacSigner[F[_] : Sync]: JwtSigner[F, JwtHmacAlgorithm, SecretKey] = new JwtSigner[F, JwtHmacAlgorithm, SecretKey] {
    override def sign(jwt: Jwt, algorithm: JwtHmacAlgorithm, key: SecretKey): F[SignedJwt] = Sync[F].delay {
      val signature = JwtUtils.sign(
        jwt.encode.getBytes(StandardCharsets.UTF_8),
        key,
        algorithm match {
          case HS256 => pdi.jwt.JwtAlgorithm.HS256
          case HS384 => pdi.jwt.JwtAlgorithm.HS384
          case HS512 => pdi.jwt.JwtAlgorithm.HS512
        }
      )
      SignedJwt(jwt, signature)
    }
  }

  implicit def asymmetricSigner[F[_] : Sync]: JwtSigner[F, JwtAsymmetricAlgorithm, PrivateKey] = new JwtSigner[F, JwtAsymmetricAlgorithm, PrivateKey] {
    override def sign(jwt: Jwt, algorithm: JwtAsymmetricAlgorithm, key: PrivateKey): F[SignedJwt] = Sync[F].delay {
      val signature = JwtUtils.sign(
        jwt.encode.getBytes(StandardCharsets.UTF_8),
        key,
        algorithm match {
          case RS256 => pdi.jwt.JwtAlgorithm.RS256
          case RS384 => pdi.jwt.JwtAlgorithm.RS384
          case RS512 => pdi.jwt.JwtAlgorithm.RS512
          case ES256 => pdi.jwt.JwtAlgorithm.ES256
          case ES384 => pdi.jwt.JwtAlgorithm.ES384
          case ES512 => pdi.jwt.JwtAlgorithm.ES512
        }
      )
      SignedJwt(jwt, signature)
    }
  }

  implicit def hmacVerifier[F[_] : Sync]: JwtVerifier[F, JwtHmacAlgorithm, SecretKey] = new DefaultVerifier[F, JwtHmacAlgorithm, SecretKey] {
    override def verify(signedJwt: SignedJwt, algorithm: JwtHmacAlgorithm, key: SecretKey): F[Either[Throwable, Jwt]] = Sync[F].delay {
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
      if (verified) Right(signedJwt.jwt) else Left(new JwtInvalidSignatureException())
    }
  }

  implicit def asymmetricVerifier[F[_] : Sync]: JwtVerifier[F, JwtAsymmetricAlgorithm, PublicKey] = new DefaultVerifier[F, JwtAsymmetricAlgorithm, PublicKey] {
    override def verify(signedJwt: SignedJwt, algorithm: JwtAsymmetricAlgorithm, key: PublicKey): F[Either[Throwable, Jwt]] = Sync[F].delay {
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
      if (verified) Right(signedJwt.jwt) else Left(new JwtInvalidSignatureException())
    }
  }
}
