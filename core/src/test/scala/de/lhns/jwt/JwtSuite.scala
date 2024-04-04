package de.lhns.jwt

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import de.lhns.jwt.Jwt.{JwtHeader, JwtPayload}
import io.circe.Json
import munit.FunSuite
import sun.security.provider.certpath.X509CertPath

import java.security.{InvalidAlgorithmParameterException, KeyStore, PrivateKey}
import java.security.cert.{CertPath, CertPathValidator, CertPathValidatorException, PKIXCertPathValidatorResult, PKIXParameters, X509Certificate}
import java.util.Base64
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import scala.collection.immutable.ListMap
import scala.util.Random
import scala.jdk.CollectionConverters._
import JwtScalaImpl._
import cats.syntax.all._
import de.lhns.jwt.JwtAlgorithm.JwtAsymmetricAlgorithm

class JwtSuite extends FunSuite {
  test("test") {
    val jwt = Jwt(
      JwtHeader(ListMap("alg" -> Json.fromString("RS512"), "typ" -> Json.fromString("JWT"))),
      JwtPayload()
    )
    println(jwt)
    println(jwt.encode)
    val bytes: Array[Byte] = Random.nextBytes(20)
    println("secret " + Base64.getUrlEncoder.withoutPadding.encodeToString(bytes))
    val secretKey: SecretKey = new SecretKeySpec(bytes, "HmacSHA256")
    val signedJwt = jwt.sign[IO](JwtAlgorithm.HS256, secretKey).unsafeRunSync()(IORuntime.global)
    println(signedJwt.encode)
    println(signedJwt.verify[IO](JwtAlgorithm.HS256, secretKey).unsafeRunSync()(IORuntime.global))

    def sign(jwt: Jwt, certPath: X509CertPath, privateKey: PrivateKey): IO[SignedJwt] = {
      jwt.modifyHeader(_.withX509CertificateChain(Some(certPath))).sign[IO](JwtAlgorithm.RS512, privateKey)
    }

    def validateCertPath(
                          certPath: CertPath,
                          keyStore: KeyStore,
                          pkixParameters: PKIXParameters => Unit = _.setRevocationEnabled(false)
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

    def verify(signedJwt: SignedJwt,
               keyStore: KeyStore,
               pkixParameters: PKIXParameters => Unit = _.setRevocationEnabled(false),
               options: JwtValidationOptions = JwtValidationOptions.default
              ): IO[Either[Throwable, Jwt]] = {
      signedJwt.header.x509CertificateChain.map(validateCertPath(_, keyStore, pkixParameters)) match {
        case Some(Right(result)) =>
          signedJwt.header.algorithm match {
            case Some(algorithm: JwtAsymmetricAlgorithm) =>
              signedJwt.verify[IO](algorithm, result.getPublicKey, options)

            case _ =>
              IO.pure(Left(new IllegalArgumentException("unsupported algorithm for cert path validation")))
          }

        case Some(Left(throwable)) =>
          IO.pure(Left(throwable))

        case None =>
          IO.pure(Left(new IllegalArgumentException("x5c claim required for cert validation")))
      }

    }
  }
}
