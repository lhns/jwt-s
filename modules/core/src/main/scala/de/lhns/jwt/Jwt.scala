package de.lhns.jwt

import cats.syntax.either._
import de.lhns.jwt.Jwt._
import io.circe.syntax._
import io.circe.{Codec, Decoder, Encoder, Json}

import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.security.cert.{CertPath, CertificateFactory}
import java.time.Instant
import scala.collection.immutable.ListMap
import scala.jdk.CollectionConverters._

final case class Jwt(
                      header: JwtHeader = JwtHeader(),
                      payload: JwtPayload = JwtPayload()
                    ) {
  def withHeader(header: JwtHeader): Jwt = copy(header = header)

  def withPayload(payload: JwtPayload): Jwt = copy(payload = payload)

  def modifyHeader(f: JwtHeader => JwtHeader): Jwt = withHeader(f(header))

  def modifyPayload(f: JwtPayload => JwtPayload): Jwt = withPayload(f(payload))

  def reencode: Jwt = copy(
    header = header.reencode,
    payload = payload.reencode
  )

  def encode: String = s"${header.encode}.${payload.encode}"

  def sign[F[_]](jwtSigner: JwtSigner[F]): F[SignedJwt] =
    jwtSigner.sign(this)
}

object Jwt {
  trait JwtComponent {
    type Self <: JwtComponent

    def claims: ListMap[String, Json]

    def withClaims(claims: ListMap[String, Json]): Self

    final def modifyClaims(f: ListMap[String, Json] => ListMap[String, Json]): Self =
      withClaims(f(claims))

    final def claim[A: Decoder](name: String): Option[A] =
      claims.get(name).map(_.as[A].toTry.get)

    final def withClaim[A: Encoder](name: String, valueOption: Option[A]): Self =
      withClaims(valueOption.fold(
        claims.filterNot(_._1 == name)
      )(value =>
        claims.updated(name, value.asJson)
      ))

    def reencode: Self

    def encode: String
  }

  trait JwtHeaderClaims extends JwtComponent {
    private[Jwt] lazy val typOption = claim[String]("typ")

    def typ: String = typOption.get

    lazy val algorithm: Option[JwtAlgorithm] = claim[String]("alg").flatMap(JwtAlgorithm.fromString)

    def withAlgorithm(algorithm: Option[JwtAlgorithm]): Self = withClaim("alg", Some(JwtAlgorithm.toString(algorithm)))

    lazy val contentType: Option[String] = claim[String]("cty")

    def withContentType(contentType: Option[String]): Self = withClaim("cty", contentType)

    lazy val keyId: Option[String] = claim[String]("kid")

    def withKeyId(keyId: Option[String]): Self = withClaim("kid", keyId)

    // https://www.rfc-editor.org/rfc/rfc7515

    lazy val x509Url: Option[String] = claim[String]("x5u")

    def withX509Url(x509Url: Option[String]): Self = withClaim("x5u", x509Url)

    lazy val x509CertificateChain: Option[CertPath] = {
      lazy val certificateFactory = CertificateFactory.getInstance("X509")
      claim[Seq[String]]("x5c").map { elems =>
        val certs = elems.map { certBase64 =>
          val certBytes = decodeBase64(certBase64).valueOr(throw _)
          certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes))
        }
        certificateFactory.generateCertPath(certs.asJava)
      }
    }

    def withX509CertificateChain(x509CertificateChain: Option[CertPath]): Self =
      withClaim(
        "x5c",
        x509CertificateChain.map(_.getCertificates.asScala.map(cert => encodeBase64Padded(cert.getEncoded)).toSeq)
      )

    lazy val x509CertificateSha1Thumbprint: Option[Array[Byte]] =
      claim[String]("x5t").map(decodeBase64Url(_).valueOr(throw _))

    def withX509CertificateSha1Thumbprint(x509CertificateSha1Thumbprint: Option[Array[Byte]]): Self =
      withClaim("x5t", x509CertificateSha1Thumbprint.map(encodeBase64Url))

    lazy val x509CertificateSha256Thumbprint: Option[Array[Byte]] =
      claim[String]("x5t#S256").map(decodeBase64Url(_).valueOr(throw _))

    def withX509CertificateSha256Thumbprint(x509CertificateSha256Thumbprint: Option[Array[Byte]]): Self =
      withClaim("x5t#S256", x509CertificateSha256Thumbprint.map(encodeBase64Url))
  }

  case class JwtHeader private(
                                claims: ListMap[String, Json],
                                encoded: Option[String]
                              ) extends JwtComponent with JwtHeaderClaims {
    override type Self = JwtHeader

    override def withClaims(claims: ListMap[String, Json]): JwtHeader =
      if (claims == this.claims) this
      else JwtHeader(claims)

    private[Jwt] def withEncoded(encoded: String): JwtHeader = new JwtHeader(claims, Some(encoded))

    @deprecated
    private def copy(claims: ListMap[String, Json], encoded: Option[String]): JwtHeader =
      throw new UnsupportedOperationException()

    def copy(claims: ListMap[String, Json] = claims): JwtHeader = withClaims(claims)

    override def reencode: JwtHeader = JwtHeader(claims)

    override def encode: String = encoded.getOrElse(
      encodeBase64Url((this: JwtHeader).asJson.noSpaces.getBytes(StandardCharsets.UTF_8))
    )
  }

  object JwtHeader {
    private val defaultClaims: ListMap[String, Json] = ListMap(
      "typ" -> Json.fromString("JWT"),
      "alg" -> Json.fromString("none")
    )

    private def normalizeClaims(claims: ListMap[String, Json]): ListMap[String, Json] =
      defaultClaims.foldRight(claims) { case (defaultEntry@(defaultKey, _), claims) =>
        if (!claims.contains(defaultKey)) ListMap(defaultEntry) ++ claims
        else claims
      }

    def apply(claims: ListMap[String, Json] = ListMap.empty): JwtHeader =
      new JwtHeader(normalizeClaims(claims), None)

    implicit val codec: Codec[JwtHeader] = Codec.from(
      Decoder[ListMap[String, Json]].map(new JwtHeader(_, None)),
      Encoder[ListMap[String, Json]].contramap(_.claims)
    )
  }

  trait JwtPayloadClaims extends JwtComponent {
    lazy val issuer: Option[String] = claim[String]("iss")

    def withIssuer(issuer: Option[String]): Self = withClaim("iss", issuer)

    lazy val subject: Option[String] = claim[String]("sub")

    def withSubject(subject: Option[String]): Self = withClaim("sub", subject)

    lazy val audience: Option[String] = claim[String]("aud")

    def withAudience(audience: Option[String]): Self = withClaim("aud", audience)

    lazy val expiration: Option[Instant] = claim[Long]("exp").map(Instant.ofEpochSecond)

    def withExpiration(expiration: Option[Instant]): Self = withClaim("exp", expiration.map(_.getEpochSecond))

    lazy val notBefore: Option[Instant] = claim[Long]("nbf").map(Instant.ofEpochSecond)

    def withNotBefore(notBefore: Option[Instant]): Self = withClaim("nbf", notBefore.map(_.getEpochSecond))

    lazy val issuedAt: Option[Instant] = claim[Long]("iat").map(Instant.ofEpochSecond)

    def withIssuedAt(issuedAt: Option[Instant]): Self = withClaim("iat", issuedAt.map(_.getEpochSecond))

    lazy val jwtId: Option[String] = claim[String]("jti")

    def withJwtId(jwtId: Option[String]): Self = withClaim("jti", jwtId)

    // https://www.rfc-editor.org/rfc/rfc8693.html

    lazy val actor: Option[JwtPayload] = claim[JwtPayload]("act")

    def withActor(actor: Option[JwtPayload]): Self = withClaim("act", actor)
  }

  case class JwtPayload private(
                                 claims: ListMap[String, Json],
                                 encoded: Option[String]
                               ) extends JwtComponent with JwtPayloadClaims {
    override type Self = JwtPayload

    override def withClaims(claims: ListMap[String, Json]): JwtPayload =
      if (claims == this.claims) this
      else JwtPayload(claims)

    private[Jwt] def withEncoded(encoded: String): JwtPayload = new JwtPayload(claims, Some(encoded))

    @deprecated
    private def copy(claims: ListMap[String, Json], encoded: Option[String]): JwtPayload =
      throw new UnsupportedOperationException()

    def copy(claims: ListMap[String, Json] = claims): JwtPayload = withClaims(claims)

    override def reencode: JwtPayload = JwtPayload(claims)

    def encode: String = encoded.getOrElse(
      encodeBase64Url((this: JwtPayload).asJson.noSpaces.getBytes(StandardCharsets.UTF_8))
    )
  }

  object JwtPayload {
    def apply(claims: ListMap[String, Json] = ListMap.empty): JwtPayload =
      new JwtPayload(claims, None)

    implicit val codec: Codec[JwtPayload] = Codec.from(
      Decoder[ListMap[String, Json]].map(new JwtPayload(_, None)),
      Encoder[ListMap[String, Json]].contramap(_.claims)
    )
  }

  implicit val codec: Codec[Jwt] = Codec.from(
    Decoder[String].emapTry(Jwt.decode(_).toTry),
    Encoder[String].contramap(_.encode)
  )

  def decodeComponents(headerBase64: String, payloadBase64: String): Either[Throwable, Jwt] =
    for {
      headerBytes <- decodeBase64Url(headerBase64)
      payloadBytes <- decodeBase64Url(payloadBase64)
      headerString <- Either.catchNonFatal(new String(headerBytes, StandardCharsets.UTF_8))
      payloadString <- Either.catchNonFatal(new String(payloadBytes, StandardCharsets.UTF_8))
      header <- io.circe.parser.decode[JwtHeader](headerString)
      payload <- io.circe.parser.decode[JwtPayload](payloadString)
      _ <- header.typOption.filter(_ == "JWT").toRight(new IllegalArgumentException("typ must be `JWT`"))
    } yield Jwt(
      header = header.withEncoded(headerBase64),
      payload = payload.withEncoded(payloadBase64)
    )

  def decode(string: String): Either[Throwable, Jwt] = {
    string.split("\\.", -1).toList match {
      case headerBase64 +: payloadBase64 +: Nil =>
        decodeComponents(headerBase64, payloadBase64)

      case _ =>
        Left(new IllegalArgumentException("must be of format <header>.<payload>"))
    }
  }
}
