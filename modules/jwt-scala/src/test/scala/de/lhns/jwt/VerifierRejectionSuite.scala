package de.lhns.jwt

import cats.effect.IO
import de.lhns.jwt.jwtscala.JwtScala._
import munit.CatsEffectSuite

import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.util.Base64
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/** Malformed or hostile tokens must be rejected as `Left`, never raised as an error and never accepted. */
class VerifierRejectionSuite extends CatsEffectSuite {
  private val secretKey: SecretKey = new SecretKeySpec("0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8), "HmacSHA256")

  private lazy val ecKeyPair = {
    val gen = KeyPairGenerator.getInstance("EC")
    gen.initialize(256)
    gen.generateKeyPair()
  }

  private def b64(string: String): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(string.getBytes(StandardCharsets.UTF_8))

  private def b64(bytes: Array[Byte]): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(bytes)

  private def token(header: String, payload: String, signature: Array[Byte]): SignedJwt =
    SignedJwt.decode(s"${b64(header)}.${b64(payload)}.${b64(signature)}").toTry.get

  /** HS256 token with a valid signature, so only the claims can be at fault. */
  private def hmacToken(payload: String, header: String = """{"typ":"JWT","alg":"HS256"}"""): SignedJwt = {
    val signingInput = s"${b64(header)}.${b64(payload)}"
    val signature = pdi.jwt.JwtUtils.sign(signingInput.getBytes(StandardCharsets.UTF_8), secretKey, pdi.jwt.JwtAlgorithm.HS256)
    token(header, payload, signature)
  }

  private def assertRejected(io: IO[Either[Throwable, Jwt]]): IO[Unit] =
    io.attempt.map {
      case Left(raised) => fail(s"verification raised instead of returning Left: $raised")
      case Right(Right(_)) => fail("token was accepted")
      case Right(Left(_)) => ()
    }

  private val hmac = hmacVerifier[IO](secretKey)

  test("sanity: valid hmac token is accepted") {
    hmacToken("""{"exp":9999999999}""").verify[IO](hmac).map(r => assert(r.isRight, r))
  }

  test("exp as string") {
    assertRejected(hmacToken("""{"exp":"abc"}""").verify[IO](hmac))
  }

  test("exp as float") {
    assertRejected(hmacToken("""{"exp":9999999999.5}""").verify[IO](hmac))
  }

  test("exp out of range") {
    assertRejected(hmacToken("""{"exp":9223372036854775807}""").verify[IO](hmac))
  }

  test("alg as number") {
    assertRejected(hmacToken("{}", """{"typ":"JWT","alg":1}""").verify[IO](hmac))
  }

  test("alg none with requireAlgorithm=false, hmac verifier") {
    val verifier = hmacVerifier[IO](secretKey, options = JwtValidationOptions(requireAlgorithm = false))
    assertRejected(token("""{"typ":"JWT","alg":"none"}""", "{}", Array.emptyByteArray).verify[IO](verifier))
  }

  test("alg none with requireAlgorithm=false, asymmetric verifier") {
    val verifier = asymmetricVerifier[IO](ecKeyPair.getPublic, options = JwtValidationOptions(requireAlgorithm = false))
    assertRejected(token("""{"typ":"JWT","alg":"none"}""", "{}", Array.emptyByteArray).verify[IO](verifier))
  }

  private lazy val ecVerifier = asymmetricVerifier[IO](ecKeyPair.getPublic)

  test("ES256 with garbage signature") {
    assertRejected(token("""{"typ":"JWT","alg":"ES256"}""", "{}", Array.fill[Byte](10)(7)).verify[IO](ecVerifier))
  }

  test("ES256 with zero signature") {
    assertRejected(token("""{"typ":"JWT","alg":"ES256"}""", "{}", new Array[Byte](64)).verify[IO](ecVerifier))
  }

  test("RS256 header with EC public key") {
    assertRejected(token("""{"typ":"JWT","alg":"RS256"}""", "{}", new Array[Byte](256)).verify[IO](ecVerifier))
  }

  private lazy val emptyKeyStore = {
    val keyStore = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType)
    keyStore.load(null, Array[Char]())
    keyStore
  }

  // `verify` is called eagerly (outside of IO) to prove it does not throw synchronously
  test("x5c with garbage certificate") {
    val io = token("""{"typ":"JWT","alg":"RS256","x5c":["AAAA"]}""", "{}", new Array[Byte](256))
      .verify[IO](certPathVerifier[IO](emptyKeyStore))
    assertRejected(io)
  }

  test("empty x5c") {
    val io = token("""{"typ":"JWT","alg":"RS256","x5c":[]}""", "{}", new Array[Byte](256))
      .verify[IO](certPathVerifier[IO](emptyKeyStore))
    assertRejected(io)
  }

  test("x5c with wrong type") {
    val io = token("""{"typ":"JWT","alg":"RS256","x5c":"abc"}""", "{}", new Array[Byte](256))
      .verify[IO](certPathVerifier[IO](emptyKeyStore))
    assertRejected(io)
  }

  test("aud as number with requireAudience") {
    val verifier = hmacVerifier[IO](secretKey, options = JwtValidationOptions(requireAudience = true))
    assertRejected(hmacToken("""{"aud":1}""").verify[IO](verifier))
  }
}
