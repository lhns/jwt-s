package de.lhns.jwt

import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.security.cert.{CertPath, CertificateFactory}
import java.security.spec.PKCS8EncodedKeySpec
import java.security.{KeyFactory, KeyStore, PrivateKey}
import java.util.Base64
import scala.jdk.CollectionConverters._
import scala.util.control.NonFatal

/** Helpers to load keys and certificates from PEM or DER bytes. Error messages never contain the input. */
object JwtKeys {
  private val PemMarker = "-----BEGIN"
  private val PemLabel = """-----BEGIN ([A-Z0-9 ]+)-----""".r
  private val ConvertHint = "openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem"

  private def attempt[A](f: => A): Either[Throwable, A] =
    try Right(f) catch {
      case NonFatal(e) => Left(e)
    }

  /** Loads an unencrypted PKCS#8 private key (RSA or EC) from PEM (`BEGIN PRIVATE KEY`) or raw DER.
    * Other formats (`BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`, `BEGIN ENCRYPTED PRIVATE KEY`) are rejected;
    * convert with `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem`.
    */
  def privateKey(bytes: Array[Byte]): Either[Throwable, PrivateKey] =
    for {
      der <- privateKeyDer(bytes)
      key <- {
        val spec = new PKCS8EncodedKeySpec(der)
        Iterator("RSA", "EC")
          .map(algorithm => attempt(KeyFactory.getInstance(algorithm).generatePrivate(spec)))
          .collectFirst { case Right(key) => key }
          .toRight[Throwable](new IllegalArgumentException(
            s"Not a valid RSA or EC PKCS#8 private key. Convert with: $ConvertHint"
          ))
      }
    } yield key

  private def privateKeyDer(bytes: Array[Byte]): Either[Throwable, Array[Byte]] = {
    val text = new String(bytes, StandardCharsets.ISO_8859_1)
      .dropWhile(c => c.isWhitespace || c == 'ï' || c == '»' || c == '¿')
    if (!text.startsWith(PemMarker)) Right(bytes)
    else PemLabel.findFirstMatchIn(text).map(_.group(1)) match {
      case Some("PRIVATE KEY") =>
        attempt {
          val body = text.linesIterator.map(_.trim).filterNot(_.startsWith("-----")).mkString
          Base64.getMimeDecoder.decode(body)
        }.left.map(_ => new IllegalArgumentException("Invalid base64 in PEM private key"))

      case label =>
        Left(new IllegalArgumentException(
          s"Unsupported PEM type${label.fold("")(l => s" '$l'")} (only PKCS#8 'PRIVATE KEY' is supported). " +
            s"Convert with: $ConvertHint"
        ))
    }
  }

  private def certificates(bytes: Array[Byte]): Either[Throwable, List[java.security.cert.Certificate]] =
    attempt(CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(bytes)).asScala.toList)
      .left.map(e => new IllegalArgumentException("Invalid certificate data: " + e.getClass.getSimpleName, e))
      .flatMap(certs => Either.cond(certs.nonEmpty, certs, new IllegalArgumentException("No certificates found")))

  /** Loads a certificate chain from a PEM bundle or a single DER certificate.
    * The order is that of the input; the leaf certificate must come first.
    */
  def certPath(bytes: Array[Byte]): Either[Throwable, CertPath] =
    certificates(bytes).flatMap(certs =>
      attempt(CertificateFactory.getInstance("X.509").generateCertPath(certs.asJava))
    )

  /** Loads every certificate of a PEM bundle or a single DER certificate into a fresh in-memory trust store.
    * Intended for `JwtCertPath.verifier` / `JwtScala.certPathVerifier`.
    */
  def trustStore(bytes: Array[Byte]): Either[Throwable, KeyStore] =
    certificates(bytes).flatMap(certs =>
      attempt {
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType)
        keyStore.load(null, null)
        certs.zipWithIndex.foreach { case (cert, i) => keyStore.setCertificateEntry(s"cert-$i", cert) }
        keyStore
      }
    )
}
