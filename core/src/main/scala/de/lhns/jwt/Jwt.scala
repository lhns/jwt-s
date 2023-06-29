package de.lhns.jwt

import cats.syntax.bifunctor._
import cats.syntax.either._
import de.lhns.jwt.Jwt._
import de.lhns.jwt.Jwt.SignedJwt.VerifyPartiallyApplied
import io.circe.syntax._
import io.circe.{Codec, Decoder, Encoder, Json}
import scodec.bits.Bases.Alphabets.Base64Url
import scodec.bits.ByteVector

import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Base64
import scala.collection.immutable.ListMap

case class Jwt(
                header: JwtHeader,
                payload: JwtPayload,
                headerBase64: Option[String],
                payloadBase64: Option[String]
              ) {
  def copy(
            header: JwtHeader = header,
            payload: JwtPayload = payload,
            headerBase64: Option[String] = None,
            payloadBase64: Option[String] = None
          ): Jwt = new Jwt(
    header = header,
    payload = payload,
    headerBase64 = headerBase64,
    payloadBase64 = payloadBase64
  )

  def withHeader(header: JwtHeader): Jwt = copy(header = header)

  def withPayload(payload: JwtPayload): Jwt = copy(payload = payload)

  def changeHeader(f: JwtHeader => JwtHeader): Jwt = withHeader(f(header))

  def changePayload(f: JwtPayload => JwtPayload): Jwt = withPayload(f(payload))

  def encode: String = List[String](
    headerBase64.getOrElse(header.encode),
    payloadBase64.getOrElse(payload.encode)
  ).mkString(".")

  def sign[F[_]]: SignPartiallyApplied[F] =
    new SignPartiallyApplied[F](this)
}

object Jwt {
  def apply(
             header: JwtHeader,
             payload: JwtPayload
           ): Jwt = new Jwt(
    header = header,
    payload = payload,
    headerBase64 = None,
    payloadBase64 = None
  )

  class SignPartiallyApplied[F[_]](jwt: Jwt) {
    def apply[Algorithm <: JwtAlgorithm, Key](
                                               algorithm: Algorithm,
                                               key: Key
                                             )(
                                               implicit signer: JwtSigner[F, Algorithm, Key]
                                             ): F[SignedJwt] =
      signer.sign(jwt.changeHeader(_.withAlgorithm(Some(algorithm))), algorithm, key)
  }

  trait JwtComponent[Self <: JwtComponent[Self]] {
    def claims: ListMap[String, Json]

    def withClaims(claims: ListMap[String, Json]): Self

    def claim[A: Decoder](name: String): Option[A] =
      claims.get(name).map(_.as[A].toTry.get)

    def withClaim[A: Encoder](name: String, valueOption: Option[A]): Self =
      withClaims(valueOption.fold(
        claims.filterNot(_._1 == name)
      )(value =>
        claims.updated(name, value.asJson)
      ))

    implicit val codec: Codec[Jwt] = Codec.from(
      Decoder[String].emapTry(Jwt.decode(_).toTry),
      Encoder[String].contramap(_.encode)
    )
  }

  case class JwtHeader private(claims: ListMap[String, Json]) extends JwtComponent[JwtHeader] {
    def copy(claims: ListMap[String, Json] = claims): JwtHeader = new JwtHeader(JwtHeader.defaultClaims ++ claims)

    override def withClaims(claims: ListMap[String, Json]): JwtHeader = copy(claims = claims)

    private[Jwt] lazy val typOption = claim[String]("typ")

    def typ: String = typOption.get

    lazy val algorithm: Option[JwtAlgorithm] = claim[String]("alg").flatMap(JwtAlgorithm.fromString)

    lazy val contentType: Option[String] = claim[String]("cty")

    lazy val keyId: Option[String] = claim[String]("kid")

    def withAlgorithm(algorithm: Option[JwtAlgorithm]): JwtHeader = withClaim("alg", Some(algorithm.fold("none")(_.name)))

    def withContentType(contentType: Option[String]): JwtHeader = withClaim("cty", contentType)

    def withKeyId(keyId: Option[String]): JwtHeader = withClaim("kid", keyId)

    private lazy val normalizedClaims: ListMap[String, Json] = JwtHeader.defaultClaims ++ claims

    def encode: String = encodeBase64Url((this: JwtHeader).asJson.noSpaces.getBytes(StandardCharsets.UTF_8))
  }

  object JwtHeader {
    private val defaultClaims: ListMap[String, Json] = ListMap(
      "typ" -> Json.fromString("JWT"),
      "alg" -> Json.fromString("none")
    )

    def apply(claims: ListMap[String, Json] = ListMap.empty): JwtHeader =
      new JwtHeader(defaultClaims ++ claims)

    def apply(algorithm: Option[JwtAlgorithm]): JwtHeader =
      JwtHeader().withAlgorithm(algorithm)

    implicit val codec: Codec[JwtHeader] = Codec.from(
      Decoder[ListMap[String, Json]].map(new JwtHeader(_)),
      Encoder[ListMap[String, Json]].contramap(_.normalizedClaims)
    )
  }

  case class JwtPayload(claims: ListMap[String, Json] = ListMap.empty) extends JwtComponent[JwtPayload] {
    override def withClaims(claims: ListMap[String, Json]): JwtPayload = copy(claims = claims)

    lazy val issuer: Option[String] = claim[String]("iss")

    lazy val subject: Option[String] = claim[String]("sub")

    lazy val audience: Option[String] = claim[String]("aud")

    lazy val expiration: Option[Instant] = claim[Long]("exp").map(Instant.ofEpochSecond)

    lazy val notBefore: Option[Instant] = claim[Long]("nbf").map(Instant.ofEpochSecond)

    lazy val issuedAt: Option[Instant] = claim[Long]("iat").map(Instant.ofEpochSecond)

    lazy val jwtId: Option[String] = claim[String]("jti")

    def withIssuer(issuer: Option[String]): JwtPayload = withClaim("iss", issuer)

    def withSubject(subject: Option[String]): JwtPayload = withClaim("sub", subject)

    def withAudience(audience: Option[String]): JwtPayload = withClaim("aud", audience)

    def withExpiration(expiration: Option[Instant]): JwtPayload = withClaim("exp", expiration.map(_.getEpochSecond))

    def withNotBefore(notBefore: Option[Instant]): JwtPayload = withClaim("nbf", notBefore.map(_.getEpochSecond))

    def withIssuedAt(issuedAt: Option[Instant]): JwtPayload = withClaim("iat", issuedAt.map(_.getEpochSecond))

    def withJwtId(jwtId: Option[String]): JwtPayload = withClaim("jti", jwtId)

    def encode: String = encodeBase64Url((this: JwtPayload).asJson.noSpaces.getBytes(StandardCharsets.UTF_8))
  }

  object JwtPayload {
    implicit val codec: Codec[JwtPayload] = Codec.from(
      Decoder[ListMap[String, Json]].map(JwtPayload(_)),
      Encoder[ListMap[String, Json]].contramap(_.claims)
    )
  }

  case class SignedJwt(
                        jwt: Jwt,
                        signature: Array[Byte]
                      ) {
    def header: JwtHeader = jwt.header

    def payload: JwtPayload = jwt.payload

    def copy(
              header: JwtHeader = jwt.header,
              payload: JwtPayload = jwt.payload,
              signature: Array[Byte] = signature
            ): SignedJwt = SignedJwt(
      header = header,
      payload = payload,
      signature = signature
    )

    def withHeader(header: JwtHeader): SignedJwt = copy(header = header)

    def withPayload(payload: JwtPayload): SignedJwt = copy(payload = payload)

    def withSignature(signature: Array[Byte]): SignedJwt = copy(signature = signature)

    def changeHeader(f: JwtHeader => JwtHeader): SignedJwt = withHeader(f(header))

    def changePayload(f: JwtPayload => JwtPayload): SignedJwt = withPayload(f(payload))

    def changeSignature(f: Array[Byte] => Array[Byte]): SignedJwt = withSignature(f(signature))

    def encode: String = List[String](jwt.encode, encodeBase64Url(signature)).mkString(".")

    def verify[F[_]]: VerifyPartiallyApplied[F] =
      new VerifyPartiallyApplied[F](this)
  }

  object SignedJwt {
    class VerifyPartiallyApplied[F[_]](jwt: SignedJwt) {
      def apply[Algorithm <: JwtAlgorithm, Key](
                                                 algorithm: Algorithm,
                                                 key: Key,
                                                 options: JwtValidationOptions = JwtValidationOptions.default
                                               )(
                                                 implicit verifier: JwtVerifier[F, Algorithm, Key]
                                               ): F[Either[Throwable, Jwt]] =
        verifier.verify(jwt.changeHeader(_.withAlgorithm(Some(algorithm))), algorithm, key, options)
    }

    def apply(
               header: JwtHeader,
               payload: JwtPayload,
               signature: Array[Byte]
             ): SignedJwt = SignedJwt(
      jwt = Jwt(
        header,
        payload
      ),
      signature = signature
    )

    def decode(string: String): Either[Throwable, SignedJwt] = {
      string.split('.').toList match {
        case headerBase64 +: payloadBase64 +: signatureBase64 +: Nil =>
          for {
            jwt <- Jwt.decodeComponents(headerBase64, payloadBase64)
            signature <- decodeBase64Url(signatureBase64)
          } yield SignedJwt(
            jwt = jwt,
            signature = signature
          )

        case _ =>
          Left(new IllegalArgumentException("must be of format <header>.<payload>.<signature>"))
      }
    }

    implicit val codec: Codec[SignedJwt] = Codec.from(
      Decoder[String].emapTry(SignedJwt.decode(_).toTry),
      Encoder[String].contramap(_.encode)
    )
  }

  def decode(string: String): Either[Throwable, Jwt] = {
    string.split('.').toList match {
      case headerBase64 +: payloadBase64 +: Nil =>
        decodeComponents(headerBase64, payloadBase64)

      case _ =>
        Left(new IllegalArgumentException("must be of format <header>.<payload>"))
    }
  }

  private def decodeBase64Url(base64: String): Either[IllegalArgumentException, Array[Byte]] =
    Either.catchOnly[IllegalArgumentException](Base64.getUrlDecoder.decode(base64))

  private def encodeBase64Url(bytes: Array[Byte]): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(bytes)

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
      header = header,
      payload = payload,
      headerBase64 = Some(headerBase64),
      payloadBase64 = Some(payloadBase64)
    )
}
