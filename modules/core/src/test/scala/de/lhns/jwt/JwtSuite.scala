package de.lhns.jwt

import de.lhns.jwt.Jwt.{JwtHeader, JwtPayload}
import io.circe.syntax._
import munit.FunSuite
import scodec.bits.ByteVector

class JwtSuite extends FunSuite {
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
}
