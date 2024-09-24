package de.lhns.jwt.jwtscala

import cats.effect.Sync
import cats.syntax.all._
import de.lhns.jwt.JwtAlgorithm._
import de.lhns.jwt.JwtCertPath.defaultPkixParameters
import de.lhns.jwt.JwtValidationException.JwtInvalidSignatureException
import de.lhns.jwt.JwtVerifier.basicVerifier
import de.lhns.jwt._
import pdi.jwt.JwtUtils
import scodec.bits.ByteVector

import java.nio.charset.StandardCharsets
import java.security.cert.{CertPath, PKIXParameters}
import java.security.{KeyStore, PrivateKey, PublicKey}
import javax.crypto.SecretKey

object JwtScala {
  def hmacSigner[F[_] : Sync](algorithm: JwtHmacAlgorithm, key: SecretKey): JwtSigner[F] =
    JwtSigner.delay[F] { jwt =>
      val jwtAlg = jwt.modifyHeader(_.withAlgorithm(Some(algorithm)))
      val signature = ByteVector.view(JwtUtils.sign(
        jwtAlg.encode.getBytes(StandardCharsets.UTF_8),
        key,
        jwtHmacAlgorithm(algorithm)
      ))
      SignedJwt(jwtAlg, signature)
    }

  def asymmetricSigner[F[_] : Sync](algorithm: JwtAsymmetricAlgorithm, key: PrivateKey): JwtSigner[F] =
    JwtSigner.delay[F] { jwt =>
      val jwtAlg = jwt.modifyHeader(_.withAlgorithm(Some(algorithm)))
      val signature = ByteVector.view(JwtUtils.sign(
        jwtAlg.encode.getBytes(StandardCharsets.UTF_8),
        key,
        jwtAsymmetricAlgorithm(algorithm)
      ))
      SignedJwt(jwtAlg, signature)
    }

  def certPathSigner[F[_] : Sync](algorithm: JwtAsymmetricAlgorithm, key: PrivateKey, certPath: CertPath): JwtSigner[F] =
    JwtCertPath.signer(certPath, asymmetricSigner(algorithm, key))

  def hmacVerifier[F[_] : Sync](
                                 key: SecretKey,
                                 algorithms: Seq[JwtHmacAlgorithm] = JwtHmacAlgorithm.values,
                                 options: JwtValidationOptions = JwtValidationOptions.default
                               ): JwtVerifier[F] =
    basicVerifier[F](algorithms, options) |+|
      JwtVerifier.delay[F] { signedJwt =>
        val verified = JwtUtils.verify(
          signedJwt.jwt.encode.getBytes(StandardCharsets.UTF_8),
          signedJwt.signature.toArrayUnsafe,
          key,
          jwtHmacAlgorithm(signedJwt.header.algorithm match {
            case Some(algorithm: JwtHmacAlgorithm) => algorithm
            case _ => throw new IllegalStateException()
          })
        )
        Either.cond(verified, (), new JwtInvalidSignatureException())
      }

  def asymmetricVerifier[F[_] : Sync](
                                       key: PublicKey,
                                       algorithms: Seq[JwtAsymmetricAlgorithm] = JwtAsymmetricAlgorithm.values,
                                       options: JwtValidationOptions = JwtValidationOptions.default
                                     ): JwtVerifier[F] =
    basicVerifier[F](algorithms, options) |+|
      JwtVerifier.delay[F] { signedJwt =>
        val verified = JwtUtils.verify(
          signedJwt.jwt.encode.getBytes(StandardCharsets.UTF_8),
          signedJwt.signature.toArrayUnsafe,
          key,
          jwtAsymmetricAlgorithm(signedJwt.header.algorithm match {
            case Some(algorithm: JwtAsymmetricAlgorithm) => algorithm
            case _ => throw new IllegalStateException()
          })
        )
        Either.cond(verified, (), new JwtInvalidSignatureException())
      }

  def certPathVerifier[F[_] : Sync](
                                     keyStore: KeyStore,
                                     algorithms: Seq[JwtAsymmetricAlgorithm] = JwtAsymmetricAlgorithm.values,
                                     options: JwtValidationOptions = JwtValidationOptions.default,
                                     pkixParameters: PKIXParameters => Unit = defaultPkixParameters
                                   ): JwtVerifier[F] =
    JwtCertPath.verifier(keyStore, asymmetricVerifier(_, algorithms, options), pkixParameters)

  private def jwtHmacAlgorithm(algorithm: JwtHmacAlgorithm): pdi.jwt.algorithms.JwtHmacAlgorithm =
    algorithm match {
      case HS256 => pdi.jwt.JwtAlgorithm.HS256
      case HS384 => pdi.jwt.JwtAlgorithm.HS384
      case HS512 => pdi.jwt.JwtAlgorithm.HS512
    }

  private def jwtAsymmetricAlgorithm(algorithm: JwtAsymmetricAlgorithm): pdi.jwt.algorithms.JwtAsymmetricAlgorithm =
    algorithm match {
      case RS256 => pdi.jwt.JwtAlgorithm.RS256
      case RS384 => pdi.jwt.JwtAlgorithm.RS384
      case RS512 => pdi.jwt.JwtAlgorithm.RS512
      case ES256 => pdi.jwt.JwtAlgorithm.ES256
      case ES384 => pdi.jwt.JwtAlgorithm.ES384
      case ES512 => pdi.jwt.JwtAlgorithm.ES512
    }
}
