package de.lhns.jwt

import cats.effect.IO
import de.lhns.jwt.Jwt.{JwtHeader, JwtPayload}
import munit.FunSuite

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import scala.util.Random

class JwtSuite extends FunSuite {
  test("test") {
    val jwt = Jwt(
      JwtHeader(),
      JwtPayload()
    )
    println(jwt)
    println(jwt.encode)
    val bytes: Array[Byte] = Random.nextBytes(20)
    val secretKey: SecretKey = new SecretKeySpec(bytes, "HmacSHA256")
    implicit val signer = new JwtSigner[IO, JwtAlgorithm.HS256.type] {
      override type Key = SecretKey

      override def sign(jwt: Jwt, algorithm: JwtAlgorithm.HS256.type, key: Key): IO[Jwt.SignedJwt] =
        IO(Jwt.SignedJwt(jwt, Array.empty))
    }

    println(jwt.sign[IO, JwtAlgorithm.HS256.type](JwtAlgorithm.HS256).apply(secretKey))
  }
}
