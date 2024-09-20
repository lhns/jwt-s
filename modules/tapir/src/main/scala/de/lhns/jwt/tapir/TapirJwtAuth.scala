package de.lhns.jwt.tapir

import cats.Monad
import cats.effect.Sync
import cats.syntax.all._
import de.lhns.jwt.{JwtVerifier, SignedJwt}
import sttp.tapir.EndpointInput.AuthType
import sttp.tapir.server.PartialServerEndpoint
import sttp.tapir.{Codec, CodecFormat, DecodeResult, Endpoint, EndpointInput, Schema, auth}

object TapirJwtAuth {
  private val jwtDescription = "JSON Web Token"

  implicit val signedJwtCodec: Codec[List[String], SignedJwt, CodecFormat.TextPlain] =
    implicitly[Codec[List[String], String, CodecFormat.TextPlain]]
      .mapDecode(string => SignedJwt.decode(string) match {
        case Left(error) => DecodeResult.Error(string, error)
        case Right(jwt) => DecodeResult.Value(jwt)
      })(_.encode).schema(Schema.string.description(jwtDescription))

  val jwtAuth: EndpointInput.Auth[SignedJwt, AuthType.Http] =
    auth.bearer[SignedJwt]().description(jwtDescription)

  def jwtSecurityLogic[F[_] : Monad, E](
                                         jwtVerifier: JwtVerifier[F],
                                         handleError: Throwable => E
                                       ): SignedJwt => F[Either[E, SignedJwt]] = { jwt =>
    jwt.verify(jwtVerifier).map(_.leftMap(handleError).as(jwt))
  }

  implicit class EndpointOps[I, E, O, R](val endpoint: Endpoint[Unit, I, E, O, R]) extends AnyVal {
    def jwtSecurity[F[_] : Sync](jwtVerifier: JwtVerifier[F])(handleError: Throwable => E): PartialServerEndpoint[SignedJwt, SignedJwt, I, E, O, R, F] =
      endpoint
        .securityIn(jwtAuth)
        .serverSecurityLogic[SignedJwt, F](
          jwtSecurityLogic[F, E](jwtVerifier, handleError)
        )
  }
}
