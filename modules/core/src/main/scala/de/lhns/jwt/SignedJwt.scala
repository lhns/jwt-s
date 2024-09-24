package de.lhns.jwt

import cats.Monad
import cats.syntax.all._
import de.lhns.jwt.Jwt.{JwtHeader, JwtPayload}
import io.circe.{Codec, Decoder, Encoder}
import scodec.bits.ByteVector

final case class SignedJwt(
                            jwt: Jwt,
                            signature: ByteVector
                          ) {
  def header: JwtHeader = jwt.header

  def payload: JwtPayload = jwt.payload

  @deprecated
  private def copy(jwt: Jwt, signature: ByteVector): SignedJwt =
    throw new UnsupportedOperationException()

  def copy(
            header: JwtHeader = jwt.header,
            payload: JwtPayload = jwt.payload,
            signature: ByteVector = signature
          ): SignedJwt = SignedJwt(
    header = header,
    payload = payload,
    signature = signature
  )

  def withHeader(header: JwtHeader): SignedJwt = copy(header = header)

  def withPayload(payload: JwtPayload): SignedJwt = copy(payload = payload)

  def withSignature(signature: ByteVector): SignedJwt = copy(signature = signature)

  def modifyHeader(f: JwtHeader => JwtHeader): SignedJwt = withHeader(f(header))

  def modifyPayload(f: JwtPayload => JwtPayload): SignedJwt = withPayload(f(payload))

  def modifySignature(f: ByteVector => ByteVector): SignedJwt = withSignature(f(signature))

  def reencode: SignedJwt = copy(
    header = header.reencode,
    payload = payload.reencode
  )

  def encode: String = {
    val encodedJwt = jwt.encode
    if (signature.isEmpty) encodedJwt
    else s"$encodedJwt.${encodeBase64Url(signature.toArrayUnsafe)}"
  }

  def verify[F[_] : Monad](jwtVerifier: JwtVerifier[F]): F[Either[Throwable, Jwt]] =
    jwtVerifier.verify(this).map(_.as(jwt))
}

object SignedJwt {
  def apply(
             header: JwtHeader,
             payload: JwtPayload,
             signature: ByteVector
           ): SignedJwt = SignedJwt(
    jwt = Jwt(
      header,
      payload
    ),
    signature = signature
  )

  implicit val codec: Codec[SignedJwt] = Codec.from(
    Decoder[String].emapTry(SignedJwt.decode(_).toTry),
    Encoder[String].contramap(_.encode)
  )

  def decodeComponents(headerBase64: String, payloadBase64: String, signatureBase64: String): Either[Throwable, SignedJwt] =
    for {
      jwt <- Jwt.decodeComponents(headerBase64, payloadBase64)
      signature <-
        if (signatureBase64.isEmpty) Right(ByteVector.empty)
        else decodeBase64Url(signatureBase64).map(ByteVector.view)
    } yield SignedJwt(
      jwt = jwt,
      signature = signature
    )

  def decode(string: String): Either[Throwable, SignedJwt] = {
    string.split("\\.", -1).toList match {
      case headerBase64 +: payloadBase64 +: signatureBase64 +: Nil =>
        decodeComponents(headerBase64, payloadBase64, signatureBase64)

      case headerBase64 +: payloadBase64 +: Nil =>
        decodeComponents(headerBase64, payloadBase64, "")

      case _ =>
        Left(new IllegalArgumentException("must be of format <header>.<payload>.<signature>"))
    }
  }
}