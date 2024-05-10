package de.lhns.jwt

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import de.lhns.jwt.Jwt.{JwtHeader, JwtPayload}
import de.lhns.jwt.jwtscala.JwtScala._
import io.circe.Json
import munit.FunSuite

import java.util.Base64
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import scala.collection.immutable.ListMap
import scala.util.Random

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
    val signedJwt = jwt.sign[IO](hmacSigner(JwtAlgorithm.HS256, secretKey)).unsafeRunSync()(IORuntime.global)
    println(signedJwt.encode)
    println(signedJwt.verify[IO](hmacVerifier(secretKey, algorithms = Seq(JwtAlgorithm.HS256))).unsafeRunSync()(IORuntime.global))
  }
}
