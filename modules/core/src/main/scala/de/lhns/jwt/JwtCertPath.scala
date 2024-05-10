package de.lhns.jwt

import cats.Monad
import cats.syntax.all._
import sun.security.provider.certpath.X509CertPath

import java.security.cert._
import java.security.{InvalidAlgorithmParameterException, KeyStore, PublicKey}

object JwtCertPath {
  def verifier[F[_] : Monad](
                              keyStore: KeyStore,
                              pkixParameters: PKIXParameters => Unit = defaultPkixParameters,
                              verifier: PublicKey => JwtVerifier[F]
                            ): JwtVerifier[F] = JwtVerifier[F] { signedJwt: SignedJwt =>
    signedJwt.header.x509CertificateChain
      .map(validateCertPath(_, keyStore, pkixParameters)) match {
      case Some(Right(result)) =>
        verifier(result.getPublicKey).verify(signedJwt)

      case Some(Left(throwable)) =>
        Monad[F].pure(Left(throwable))

      case None =>
        Monad[F].pure(Left(new IllegalArgumentException("x5c claim required for cert validation")))
    }
  }

  def signer[F[_]](certPath: X509CertPath, signer: JwtSigner[F]): JwtSigner[F] =
    JwtSigner[F] { jwt: Jwt =>
      signer.sign(jwt.modifyHeader(_.withX509CertificateChain(Some(certPath))))
    }

  val defaultPkixParameters: PKIXParameters => Unit = _.setRevocationEnabled(false)

  private def validateCertPath(
                                certPath: CertPath,
                                keyStore: KeyStore,
                                pkixParameters: PKIXParameters => Unit = defaultPkixParameters
                              ): Either[CertPathValidatorException, PKIXCertPathValidatorResult] = {
    val validator = CertPathValidator.getInstance("PKIX")
    Either
      .catchOnly[InvalidAlgorithmParameterException] {
        new PKIXParameters(keyStore)
      }
      .leftMap(new CertPathValidatorException(_))
      .flatMap { params =>
        pkixParameters(params)
        Either.catchOnly[CertPathValidatorException] {
          validator.validate(certPath, params).asInstanceOf[PKIXCertPathValidatorResult]
        }
      }
  }
}
