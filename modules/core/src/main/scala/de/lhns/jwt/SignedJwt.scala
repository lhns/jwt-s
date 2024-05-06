package de.lhns.jwt

import de.lhns.jwt.Jwt.{JwtHeader, JwtPayload}
import io.circe.{Codec, Decoder, Encoder}

final case class SignedJwt(
                            jwt: Jwt,
                            signature: Array[Byte]
                          ) {
  def header: JwtHeader = jwt.header

  def payload: JwtPayload = jwt.payload

  @deprecated
  private def copy(jwt: Jwt, signature: Array[Byte]): SignedJwt =
    throw new UnsupportedOperationException()

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

  def modifyHeader(f: JwtHeader => JwtHeader): SignedJwt = withHeader(f(header))

  def modifyPayload(f: JwtPayload => JwtPayload): SignedJwt = withPayload(f(payload))

  def modifySignature(f: Array[Byte] => Array[Byte]): SignedJwt = withSignature(f(signature))

  def reencode: SignedJwt = copy(
    header = header.reencode,
    payload = payload.reencode
  )

  def encode: String = s"${jwt.encode}.${encodeBase64Url(signature)}"

  def verify[F[_]](jwtVerifier: JwtVerifier[F]): F[Either[Throwable, Jwt]] =
    jwtVerifier.verify(this)
}

object SignedJwt {
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

  implicit val codec: Codec[SignedJwt] = Codec.from(
    Decoder[String].emapTry(SignedJwt.decode(_).toTry),
    Encoder[String].contramap(_.encode)
  )

  def decodeComponents(headerBase64: String, payloadBase64: String, signatureBase64: String): Either[Throwable, SignedJwt] =
    for {
      jwt <- Jwt.decodeComponents(headerBase64, payloadBase64)
      signature <- decodeBase64Url(signatureBase64)
    } yield SignedJwt(
      jwt = jwt,
      signature = signature
    )

  def decode(string: String): Either[Throwable, SignedJwt] = {
    string.split('.').toList match {
      case headerBase64 +: payloadBase64 +: signatureBase64 +: Nil =>
        decodeComponents(headerBase64, payloadBase64, signatureBase64)

      case _ =>
        Left(new IllegalArgumentException("must be of format <header>.<payload>.<signature>"))
    }
  }
}