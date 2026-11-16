package de.lhns.jwt

import cats.effect.IO
import de.lhns.jwt.jwtscala.JwtScala._
import munit.CatsEffectSuite

import java.nio.charset.StandardCharsets
import java.util.Base64
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class ClaimValidationSuite extends CatsEffectSuite {
  private val secretKey: SecretKey = new SecretKeySpec("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8), "HmacSHA256")

  private def b64(string: String): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(string.getBytes(StandardCharsets.UTF_8))

  /** HS256 token with a valid signature, so only the claims can be at fault. */
  private def hmacToken(payload: String, header: String = """{"typ":"JWT","alg":"HS256"}"""): SignedJwt = {
    val signingInput = s"${b64(header)}.${b64(payload)}"
    val signature = pdi.jwt.JwtUtils.sign(signingInput.getBytes(StandardCharsets.UTF_8), secretKey, pdi.jwt.JwtAlgorithm.HS256)
    SignedJwt.decode(s"$signingInput.${Base64.getUrlEncoder.withoutPadding.encodeToString(signature)}").toTry.get
  }

  private def verify(signedJwt: SignedJwt, options: JwtValidationOptions): IO[Either[Throwable, Jwt]] =
    signedJwt.verify[IO](hmacVerifier[IO](secretKey, options = options))

  private def assertAccepted(io: IO[Either[Throwable, Jwt]]): IO[Unit] =
    io.map(result => assert(result.isRight, result))

  private def assertRejectedWith[E <: Throwable : scala.reflect.ClassTag](io: IO[Either[Throwable, Jwt]]): IO[Unit] =
    io.map {
      case Left(_: E) => ()
      case other => fail(s"expected Left of ${implicitly[scala.reflect.ClassTag[E]].runtimeClass.getSimpleName}, got $other")
    }

  import JwtValidationException._

  test("typ JWT is accepted by default") {
    assertAccepted(verify(hmacToken("{}"), JwtValidationOptions.default))
  }

  test("typ at+jwt is rejected by default") {
    assertRejectedWith[JwtInvalidTypeException](
      verify(hmacToken("{}", """{"typ":"at+jwt","alg":"HS256"}"""), JwtValidationOptions.default)
    )
  }

  test("typ at+jwt is accepted when listed, case-insensitively") {
    val options = JwtValidationOptions(acceptedTypes = Set("AT+JWT"))
    assertAccepted(verify(hmacToken("{}", """{"typ":"at+jwt","alg":"HS256"}"""), options))
  }

  test("typ not listed in acceptedTypes is rejected") {
    val options = JwtValidationOptions(acceptedTypes = Set("at+jwt"))
    assertRejectedWith[JwtInvalidTypeException](verify(hmacToken("{}"), options))
  }

  test("missing typ is rejected") {
    assertRejectedWith[JwtInvalidTypeException](
      verify(hmacToken("{}", """{"alg":"HS256"}"""), JwtValidationOptions.default)
    )
  }

  test("decode no longer enforces typ") {
    assert(SignedJwt.decode(s"${b64("""{"typ":"at+jwt","alg":"HS256"}""")}.${b64("{}")}").isRight)
  }

  test("aud array satisfies requireAudience") {
    assertAccepted(verify(hmacToken("""{"aud":["a","b"]}"""), JwtValidationOptions(requireAudience = true)))
  }

  test("audiences accepts string and array") {
    assertEquals(hmacToken("""{"aud":"a"}""").payload.audiences, Some(Seq("a")))
    assertEquals(hmacToken("""{"aud":["a","b"]}""").payload.audiences, Some(Seq("a", "b")))
    assertEquals(hmacToken("{}").payload.audiences, None)
  }

  test("expectedAudience matches string aud") {
    assertAccepted(verify(hmacToken("""{"aud":"a"}"""), JwtValidationOptions(expectedAudience = Some("a"))))
  }

  test("expectedAudience matches any element of array aud") {
    assertAccepted(verify(hmacToken("""{"aud":["x","a"]}"""), JwtValidationOptions(expectedAudience = Some("a"))))
  }

  test("expectedAudience rejects mismatch") {
    assertRejectedWith[JwtInvalidAudienceException](
      verify(hmacToken("""{"aud":["x","y"]}"""), JwtValidationOptions(expectedAudience = Some("a")))
    )
  }

  test("expectedAudience rejects missing aud") {
    assertRejectedWith[JwtInvalidAudienceException](
      verify(hmacToken("{}"), JwtValidationOptions(expectedAudience = Some("a")))
    )
  }

  test("expectedIssuer accepts match") {
    assertAccepted(verify(hmacToken("""{"iss":"me"}"""), JwtValidationOptions(expectedIssuer = Some("me"))))
  }

  test("expectedIssuer rejects mismatch") {
    assertRejectedWith[JwtInvalidIssuerException](
      verify(hmacToken("""{"iss":"other"}"""), JwtValidationOptions(expectedIssuer = Some("me")))
    )
  }

  test("expectedIssuer rejects missing iss") {
    assertRejectedWith[JwtInvalidIssuerException](
      verify(hmacToken("{}"), JwtValidationOptions(expectedIssuer = Some("me")))
    )
  }
}
