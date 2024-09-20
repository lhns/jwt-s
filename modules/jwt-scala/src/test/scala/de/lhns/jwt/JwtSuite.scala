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
import java.security.cert.{Certificate, CertificateFactory, X509Certificate}
import java.security.{KeyPair, KeyPairGenerator, KeyStore}
import java.time.{Instant, OffsetDateTime}
import java.util.{Base64, Date}
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import scala.util.Random

class JwtSuite extends CatsEffectSuite {
  private val jwt = Jwt(
    payload = JwtPayload()
      .withIssuer(Some("test"))
  )

  test("hmac") {
    println("jwt: " + jwt)
    val secret: Array[Byte] = Random.nextBytes(20)
    println("secret: " + Base64.getUrlEncoder.withoutPadding.encodeToString(secret))
    val secretKey: SecretKey = new SecretKeySpec(secret, "HmacSHA256")
    for {
      signedJwt <- jwt.sign[IO](hmacSigner(JwtAlgorithm.HS256, secretKey))
      encoded = signedJwt.encode
      _ = println("encoded: " + encoded)
      decodedJwt = SignedJwt.decode(encoded).toTry.get
      obtainedOrError <- decodedJwt.verify[IO](hmacVerifier(secretKey, algorithms = Seq(JwtAlgorithm.HS256)))
      obtained = obtainedOrError.toTry.get
    } yield
      assertEquals(obtained.reencode, signedJwt.jwt)
  }

  private def generateRsaKeypair(keySize: Int): KeyPair = {
    val keyGen = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(keySize)
    keyGen.genKeyPair()
  }

  private lazy val keyPair = generateRsaKeypair(4096)

  test("rsa") {
    println("jwt: " + jwt)
    for {
      signedJwt <- jwt.sign[IO](asymmetricSigner(JwtAlgorithm.RS256, keyPair.getPrivate))
      encoded = signedJwt.encode
      _ = println("encoded: " + encoded)
      decodedJwt = SignedJwt.decode(encoded).toTry.get
      obtainedOrError <- decodedJwt.verify[IO](asymmetricVerifier(keyPair.getPublic, algorithms = JwtAlgorithm.JwtRsaAlgorithm.values))
      obtained = obtainedOrError.toTry.get
    } yield
      assertEquals(obtained.reencode, signedJwt.jwt)
  }

  private def generateCertificate(
                                   keyPair: KeyPair,
                                   issuer: X500Name,
                                   serial: BigInteger,
                                   notBefore: Instant,
                                   notAfter: Instant,
                                   subject: X500Name
                                 ): X509Certificate = {
    val contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate)
    val certBuilder: JcaX509v3CertificateBuilder = new JcaX509v3CertificateBuilder(
      issuer,
      serial,
      Date.from(notBefore),
      Date.from(notAfter),
      subject,
      keyPair.getPublic
    )
    val basicConstraints = new BasicConstraints(true /*true for CA, false for EndEntity*/)
    // Basic Constraints is usually marked as critical.
    certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints)
    new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner))
  }

  private def keyStoreFromCertificates(certificates: Seq[Certificate]): KeyStore = {
    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType)
    keyStore.load(null, Array[Char]())
    certificates.zipWithIndex.foreach {
      case (certificate, i) =>
        keyStore.setCertificateEntry(i.toString, certificate)
    }
    keyStore
  }

  test("cert path") {
    println("jwt: " + jwt)
    val cert = generateCertificate(
      keyPair = keyPair,
      issuer = new X500Name("C=DE"),
      serial = new BigInteger("0"),
      notBefore = Instant.now,
      notAfter = OffsetDateTime.now.plusYears(1).toInstant,
      subject = new X500Name("C=DE")
    )
    val certPath = CertificateFactory.getInstance("X.509").generateCertPath(java.util.List.of(cert))
    for {
      signedJwt <- jwt.sign(certPathSigner[IO](
        JwtAlgorithm.RS512,
        keyPair.getPrivate,
        certPath
      ))
      encoded = signedJwt.encode
      _ = println("encoded: " + encoded)
      decodedJwt = SignedJwt.decode(encoded).toTry.get
      obtainedOrError <- decodedJwt.verify[IO](certPathVerifier(
        keyStoreFromCertificates(Seq(cert))
      ))
      obtained = obtainedOrError.toTry.get
    } yield
      assertEquals(obtained.reencode, signedJwt.jwt)
  }
}
