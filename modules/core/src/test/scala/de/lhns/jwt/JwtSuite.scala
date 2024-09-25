package de.lhns.jwt

import cats.Applicative
import cats.effect.{Clock, IO}
import de.lhns.jwt.Jwt.{JwtHeader, JwtPayload}
import de.lhns.jwt.JwtAlgorithm.{HS512, RS256}
import io.circe.syntax._
import munit.CatsEffectSuite
import scodec.bits.ByteVector

import java.time.Instant
import java.util.concurrent.TimeUnit
import scala.concurrent.duration.FiniteDuration

class JwtSuite extends CatsEffectSuite {
  lazy val jwt: Jwt = Jwt(header = JwtHeader(), payload = JwtPayload().withSubject(Some("test")))

  test("jwt") {
    val jwtJson = jwt.header.asJson.noSpaces + "." + jwt.payload.asJson.noSpaces

    assertEquals(jwtJson, """{"typ":"JWT","alg":"none"}.{"sub":"test"}""")

    val jwtEncoded = jwt.encode

    assertEquals(jwtEncoded, "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0")

    val jwtDecoded = Jwt.decode(jwtEncoded)

    assertEquals(jwtDecoded.map(_.reencode), Right(jwt))
  }

  test("signed jwt") {
    val signedJwt = SignedJwt(jwt, ByteVector(0, 1, 2, 3))

    val jwtEncoded = signedJwt.encode

    assertEquals(jwtEncoded, "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.AAECAw")

    val jwtDecoded = SignedJwt.decode(jwtEncoded)

    assertEquals(jwtDecoded.map(_.reencode), Right(signedJwt))
  }

  test("signed jwt without signature") {
    val signedJwt = SignedJwt(jwt, ByteVector.empty)

    val jwtEncoded = signedJwt.encode

    assertEquals(jwtEncoded, "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0")

    val jwtDecoded = SignedJwt.decode(jwtEncoded)

    assertEquals(jwtDecoded.map(_.reencode), Right(signedJwt))
  }

  test("exp and nbf") {
    val now = Instant.now()

    implicit val clock: Clock[IO] = new Clock[IO] {
      override def applicative: Applicative[IO] = Applicative[IO]

      override def monotonic: IO[FiniteDuration] = realTime

      override def realTime: IO[FiniteDuration] = IO.pure(FiniteDuration(now.toEpochMilli, TimeUnit.MILLISECONDS))
    }

    def jwtWithPayload(f: JwtPayload => JwtPayload): SignedJwt =
      SignedJwt(Jwt(JwtHeader().withAlgorithm(Some(RS256)), f(JwtPayload())), ByteVector.empty)

    val verifier = JwtVerifier.basicVerifier[IO](algorithms = JwtAlgorithm.values)

    val jwtExpNow = jwtWithPayload(_.withExpiration(Some(now)))
    val jwtExpFuture = jwtWithPayload(_.withExpiration(Some(now.plusSeconds(1))))
    val jwtExpPast = jwtWithPayload(_.withExpiration(Some(now.minusSeconds(1))))
    val jwtExpNone = jwtWithPayload(identity)

    val jwtNbfNow = jwtWithPayload(_.withNotBefore(Some(now)))
    val jwtNbfFuture = jwtWithPayload(_.withNotBefore(Some(now.plusSeconds(1))))
    val jwtNbfPast = jwtWithPayload(_.withNotBefore(Some(now.minusSeconds(1))))
    val jwtNbfNone = jwtWithPayload(identity)

    jwtExpNow.verify(verifier).map { result =>
      // jwt that is expired should be invalid
      assert(result.isLeft)
    } >>
      jwtExpFuture.verify(verifier).map { result =>
        // jwt that will expire in the future should be valid
        assert(result.isRight)
      } >>
      jwtExpPast.verify(verifier).map { result =>
        // jwt that has expired in the past should be invalid
        assert(result.isLeft)
      } >>
      jwtExpNone.verify(verifier).map { result =>
        // jwt that has no exp should be valid
        assert(result.isRight)
      } >>
      jwtNbfNow.verify(verifier).map { result =>
        // jwt that is currently valid should be valid
        assert(result.isRight)
      } >>
      jwtNbfFuture.verify(verifier).map { result =>
        // jwt that will be valid in the future should be invalid
        assert(result.isLeft)
      } >>
      jwtNbfPast.verify(verifier).map { result =>
        // jwt that is valid since the past should be valid
        assert(result.isRight)
      } >>
      jwtNbfNone.verify(verifier).map { result =>
        // jwt that has no nbf should be valid
        assert(result.isRight)
      }
  }

  test("algorithms") {
    val verifier = JwtVerifier.basicVerifier[IO](algorithms = Seq(JwtAlgorithm.HS512))

    SignedJwt(Jwt(JwtHeader().withAlgorithm(Some(RS256))), ByteVector.empty).verify(verifier).map { result =>
      assert(result.isLeft)
    } >> SignedJwt(Jwt(JwtHeader().withAlgorithm(Some(HS512))), ByteVector.empty).verify(verifier).map { result =>
      assert(result.isRight)
    }
  }

  test("subject required") {
    val verifier = JwtVerifier.basicVerifier[IO](
      algorithms = JwtAlgorithm.values,
      options = JwtValidationOptions.default.copy(requireSubject = true)
    )

    SignedJwt(Jwt(JwtHeader().withAlgorithm(Some(RS256))), ByteVector.empty).verify(verifier).map { result =>
      assert(result.isLeft)
    } >> SignedJwt(Jwt(JwtHeader().withAlgorithm(Some(RS256)), JwtPayload().withSubject(Some("test"))), ByteVector.empty).verify(verifier).map { result =>
      assert(result.isRight)
    }
  }

  test("algorithm required") {
    SignedJwt(Jwt(JwtHeader()), ByteVector.empty).verify(JwtVerifier.basicVerifier[IO](
      algorithms = JwtAlgorithm.values,
      options = JwtValidationOptions.default
    )).map { result =>
      assert(result.isLeft)
    } >> SignedJwt(Jwt(JwtHeader()), ByteVector.empty).verify(JwtVerifier.basicVerifier[IO](
      algorithms = JwtAlgorithm.values,
      options = JwtValidationOptions.default.copy(requireAlgorithm = false)
    )).map { result =>
      assert(result.isRight)
    }
  }
}
