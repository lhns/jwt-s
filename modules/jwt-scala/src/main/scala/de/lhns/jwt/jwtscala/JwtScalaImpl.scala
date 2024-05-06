package de.lhns.jwt.jwtscala

import cats.data.EitherT
import cats.effect.Sync
import de.lhns.jwt.JwtAlgorithm._
import de.lhns.jwt.JwtValidationException.{JwtInvalidAlgorithmException, JwtInvalidSignatureException}
import de.lhns.jwt.JwtVerifier.DefaultVerifier
import de.lhns.jwt._
import pdi.jwt.JwtUtils

import java.nio.charset.StandardCharsets
import java.security.{PrivateKey, PublicKey}
import javax.crypto.SecretKey

object JwtScalaImpl {
  def hmacSigner[F[_] : Sync](algorithm: JwtHmacAlgorithm, key: SecretKey): JwtSigner[F] = new JwtSigner[F] {
    override def sign(jwt: Jwt): F[SignedJwt] = Sync[F].delay {
      val jwtAlg = jwt.modifyHeader(_.withAlgorithm(Some(algorithm)))
      val signature = JwtUtils.sign(
        jwtAlg.encode.getBytes(StandardCharsets.UTF_8),
        key,
        algorithm match {
          case HS256 => pdi.jwt.JwtAlgorithm.HS256
          case HS384 => pdi.jwt.JwtAlgorithm.HS384
          case HS512 => pdi.jwt.JwtAlgorithm.HS512
        }
      )
      SignedJwt(jwtAlg, signature)
    }
  }

  def asymmetricSigner[F[_] : Sync](algorithm: JwtAsymmetricAlgorithm, key: PrivateKey): JwtSigner[F] = new JwtSigner[F] {
    override def sign(jwt: Jwt): F[SignedJwt] = Sync[F].delay {
      val jwtAlg = jwt.modifyHeader(_.withAlgorithm(Some(algorithm)))
      val signature = JwtUtils.sign(
        jwtAlg.encode.getBytes(StandardCharsets.UTF_8),
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
      SignedJwt(jwtAlg, signature)
    }
  }

  def hmacVerifier[F[_] : Sync](
                                 key: SecretKey,
                                 algorithms: Seq[JwtHmacAlgorithm] = JwtHmacAlgorithm.values,
                                 options: JwtValidationOptions = JwtValidationOptions.default
                               ): JwtVerifier[F] = new DefaultVerifier[F](options) {
    override def verify(signedJwt: SignedJwt): F[Either[Throwable, Jwt]] =
      (for {
        _ <- EitherT(super.verify(signedJwt))
        algorithm <- signedJwt.header.algorithm match {
          case Some(algorithm) if algorithms.contains(algorithm) => EitherT.rightT[F, Throwable](algorithm)
          case algorithm => EitherT.leftT(new JwtInvalidAlgorithmException(algorithm))
        }
        verified <- EitherT.right[Throwable](Sync[F].delay {
          JwtUtils.verify(
            signedJwt.jwt.encode.getBytes(StandardCharsets.UTF_8),
            signedJwt.signature,
            key,
            algorithm match {
              case JwtAlgorithm.HS256 => pdi.jwt.JwtAlgorithm.HS256
              case JwtAlgorithm.HS384 => pdi.jwt.JwtAlgorithm.HS384
              case JwtAlgorithm.HS512 => pdi.jwt.JwtAlgorithm.HS512
            }
          )
        })
        _ <- EitherT.cond[F](verified, (), new JwtInvalidSignatureException(): Throwable)
      } yield signedJwt.jwt).value
  }

  def asymmetricVerifier[F[_] : Sync](
                                       key: PublicKey,
                                       algorithms: Seq[JwtAsymmetricAlgorithm] = JwtAsymmetricAlgorithm.values,
                                       options: JwtValidationOptions = JwtValidationOptions.default
                                     ): JwtVerifier[F] = new DefaultVerifier[F](options) {
    override def verify(signedJwt: SignedJwt): F[Either[Throwable, Jwt]] =
      (for {
        _ <- EitherT(super.verify(signedJwt))
        algorithm <- signedJwt.header.algorithm match {
          case Some(algorithm) if algorithms.contains(algorithm) => EitherT.rightT[F, Throwable](algorithm)
          case algorithm => EitherT.leftT(new JwtInvalidAlgorithmException(algorithm))
        }
        verified <- EitherT.right[Throwable](Sync[F].delay {
          JwtUtils.verify(
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
        })
        _ <- EitherT.cond[F](verified, (), new JwtInvalidSignatureException(): Throwable)
      } yield signedJwt.jwt).value
  }
}
