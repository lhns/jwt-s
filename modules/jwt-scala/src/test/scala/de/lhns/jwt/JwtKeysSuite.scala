package de.lhns.jwt

import cats.effect.IO
import de.lhns.jwt.Jwt.JwtPayload
import de.lhns.jwt.jwtscala.JwtScala._
import munit.CatsEffectSuite
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509v3CertificateBuilder}
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.cert.X509Certificate
import java.security.{KeyPair, KeyPairGenerator}
import java.time.{Instant, OffsetDateTime}
import java.util.{Base64, Date}

class JwtKeysSuite extends CatsEffectSuite {
  private val jwt = Jwt(payload = JwtPayload().withIssuer(Some("test")))

  private def keyPair(algorithm: String, size: Int): KeyPair = {
    val gen = KeyPairGenerator.getInstance(algorithm)
    gen.initialize(size)
    gen.generateKeyPair()
  }

  private lazy val rsa = keyPair("RSA", 2048)
  private lazy val ec = keyPair("EC", 256)

  private def pem(label: String, der: Array[Byte]): String =
    s"-----BEGIN $label-----\n" +
      Base64.getMimeEncoder(64, "\n".getBytes).encodeToString(der) +
      s"\n-----END $label-----\n"

  private def utf8(s: String): Array[Byte] = s.getBytes(StandardCharsets.UTF_8)

  private def roundTrip(pair: KeyPair, keyBytes: Array[Byte], algorithm: JwtAlgorithm.JwtAsymmetricAlgorithm) = {
    val key = JwtKeys.privateKey(keyBytes).toTry.get
    for {
      signed <- jwt.sign[IO](asymmetricSigner(algorithm, key))
      result <- signed.verify[IO](asymmetricVerifier(pair.getPublic))
    } yield assert(result.isRight, result.toString)
  }

  test("rsa private key from DER")(roundTrip(rsa, rsa.getPrivate.getEncoded, JwtAlgorithm.RS256))
  test("rsa private key from PEM")(roundTrip(rsa, utf8(pem("PRIVATE KEY", rsa.getPrivate.getEncoded)), JwtAlgorithm.RS256))
  test("ec private key from DER")(roundTrip(ec, ec.getPrivate.getEncoded, JwtAlgorithm.ES256))
  test("ec private key from PEM with leading whitespace")(
    roundTrip(ec, utf8("\n  " + pem("PRIVATE KEY", ec.getPrivate.getEncoded)), JwtAlgorithm.ES256)
  )

  private def certificate(
                           subjectKey: KeyPair,
                           issuerKey: KeyPair,
                           issuer: String,
                           subject: String,
                           ca: Boolean
                         ): X509Certificate = {
    val signer = new JcaContentSignerBuilder("SHA256WithRSA").build(issuerKey.getPrivate)
    val builder = new JcaX509v3CertificateBuilder(
      new X500Name(issuer),
      BigInteger.valueOf(System.nanoTime()),
      Date.from(Instant.now.minusSeconds(60)),
      Date.from(OffsetDateTime.now.plusYears(1).toInstant),
      new X500Name(subject),
      subjectKey.getPublic
    )
    builder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, new BasicConstraints(ca))
    new JcaX509CertificateConverter().getCertificate(builder.build(signer))
  }

  test("cert bundle, trust store and private key work together") {
    val caKey = keyPair("RSA", 2048)
    val leafKey = keyPair("RSA", 2048)
    val ca = certificate(caKey, caKey, "CN=ca", "CN=ca", ca = true)
    val leaf = certificate(leafKey, caKey, "CN=ca", "CN=leaf", ca = false)
    val bundle = utf8(pem("CERTIFICATE", leaf.getEncoded) + pem("CERTIFICATE", ca.getEncoded))
    val caPem = utf8(pem("CERTIFICATE", ca.getEncoded))

    val certPath = JwtKeys.certPath(bundle).toTry.get
    assertEquals(certPath.getCertificates.size, 2)
    assertEquals(certPath.getCertificates.get(0): java.security.cert.Certificate, leaf)
    assertEquals(certPath.getCertificates.get(1): java.security.cert.Certificate, ca)
    assertEquals(JwtKeys.certPath(leaf.getEncoded).toTry.get.getCertificates.size, 1)

    assertEquals(JwtKeys.trustStore(bundle).toTry.get.size, 2)
    val caStore = JwtKeys.trustStore(caPem).toTry.get
    assertEquals(caStore.size, 1)

    val key = JwtKeys.privateKey(utf8(pem("PRIVATE KEY", leafKey.getPrivate.getEncoded))).toTry.get
    for {
      signed <- jwt.sign[IO](certPathSigner[IO](JwtAlgorithm.RS256, key, certPath))
      result <- signed.verify[IO](certPathVerifier[IO](caStore))
    } yield assert(result.isRight, result.toString)
  }

  private def leftMessage(result: Either[Throwable, _], secret: String): String = {
    val message = result.left.getOrElse(fail("expected Left")).getMessage
    assert(!message.contains(secret), message)
    message
  }

  test("rejections") {
    val garbage = "super-secret-garbage"
    assert(JwtKeys.privateKey(Array.emptyByteArray).isLeft)
    leftMessage(JwtKeys.privateKey(utf8(garbage)), garbage)
    leftMessage(JwtKeys.certPath(utf8(garbage)), garbage)
    leftMessage(JwtKeys.trustStore(utf8(garbage)), garbage)
    assert(JwtKeys.certPath(Array.emptyByteArray).isLeft)
    assert(JwtKeys.trustStore(Array.emptyByteArray).isLeft)

    val body = Base64.getEncoder.encodeToString(rsa.getPrivate.getEncoded)
    val message = leftMessage(JwtKeys.privateKey(utf8(pem("RSA PRIVATE KEY", rsa.getPrivate.getEncoded))), body.take(40))
    assert(message.contains("openssl pkcs8"), message)
    assert(JwtKeys.privateKey(utf8(pem("ENCRYPTED PRIVATE KEY", rsa.getPrivate.getEncoded))).isLeft)
    assert(JwtKeys.privateKey(utf8("-----BEGIN PRIVATE KEY-----\n!!!notbase64\n-----END PRIVATE KEY-----")).isLeft)
  }

  private val bom: Array[Byte] = Array(0xEF, 0xBB, 0xBF).map(_.toByte)

  test("key pem with text preamble") {
    roundTrip(rsa, utf8("Bag Attributes\n  localKeyID: 01\n" + pem("PRIVATE KEY", rsa.getPrivate.getEncoded)), JwtAlgorithm.RS256)
  }

  test("key pem with bom")(
    roundTrip(ec, bom ++ utf8(pem("PRIVATE KEY", ec.getPrivate.getEncoded)), JwtAlgorithm.ES256)
  )

  private lazy val selfSigned = certificate(rsa, rsa, "CN=x", "CN=x", ca = true)

  test("key and certificate in one file, both orders") {
    val keyPem = pem("PRIVATE KEY", rsa.getPrivate.getEncoded)
    val certPem = pem("CERTIFICATE", selfSigned.getEncoded)
    for {
      _ <- roundTrip(rsa, utf8(keyPem + certPem), JwtAlgorithm.RS256)
      _ <- roundTrip(rsa, utf8(certPem + keyPem), JwtAlgorithm.RS256)
    } yield ()
  }

  test("only non-pkcs8 blocks lists the labels") {
    val message = leftMessage(
      JwtKeys.privateKey(utf8(pem("CERTIFICATE", selfSigned.getEncoded))), "zzz"
    )
    assert(message.contains("CERTIFICATE") && message.contains("openssl pkcs8"), message)
  }

  test("bom-prefixed cert bundle") {
    val bundle = bom ++ utf8(pem("CERTIFICATE", selfSigned.getEncoded))
    assertEquals(JwtKeys.certPath(bundle).toTry.get.getCertificates.size, 1)
    assertEquals(JwtKeys.trustStore(bundle).toTry.get.size, 1)
  }

  test("certPath and trustStore take certificates only: key block is rejected") {
    val both = utf8(pem("PRIVATE KEY", rsa.getPrivate.getEncoded) + pem("CERTIFICATE", selfSigned.getEncoded))
    assert(JwtKeys.certPath(both).isLeft)
    assert(JwtKeys.trustStore(both).isLeft)
  }
}
