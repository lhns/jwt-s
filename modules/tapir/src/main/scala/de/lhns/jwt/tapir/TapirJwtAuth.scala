package de.lhns.jwt.tapir

import cats.Monad
import cats.data.EitherT
import cats.effect.Sync
import cats.syntax.all._
import de.lhns.jwt.{JwtVerifier, SignedJwt}
import sttp.tapir.EndpointInput.AuthType
import sttp.tapir.server.PartialServerEndpoint
import sttp.tapir.{Codec, CodecFormat, DecodeResult, Endpoint, EndpointInput, Schema, auth}

object TapirJwtAuth {
  private val jwtDescription = "JSON Web Token"

  implicit val signedJwtSchema: Schema[SignedJwt] =
    Schema.string[SignedJwt].format("jwt").description(jwtDescription)

  implicit val signedJwtCodec: Codec[List[String], SignedJwt, CodecFormat.TextPlain] =
    implicitly[Codec[List[String], String, CodecFormat.TextPlain]]
      .mapDecode(string => SignedJwt.decode(string) match {
        case Left(error) => DecodeResult.Error(string, error)
        case Right(jwt) => DecodeResult.Value(jwt)
      })(_.encode)
      .schema(signedJwtSchema)

  val jwtAuth: EndpointInput.Auth[SignedJwt, AuthType.Http] =
    auth.bearer[SignedJwt]().description(jwtDescription)

  def jwtSecurityLogicF[F[_] : Monad, E](
                                          jwtVerifier: JwtVerifier[F],
                                          handleError: Throwable => F[E]
                                        ): SignedJwt => F[Either[E, SignedJwt]] = { jwt =>
    EitherT(jwt.verify(jwtVerifier)).leftSemiflatMap(handleError).as(jwt).value
  }

  def jwtSecurityLogic[F[_] : Monad, E](
                                         jwtVerifier: JwtVerifier[F],
                                         handleError: Throwable => E
                                       ): SignedJwt => F[Either[E, SignedJwt]] =
    jwtSecurityLogicF(jwtVerifier, error => Monad[F].pure(handleError(error)))

  implicit class EndpointOps[I, E, O, R](val endpoint: Endpoint[Unit, I, E, O, R]) extends AnyVal {
    def jwtSecurityF[F[_] : Sync](jwtVerifier: JwtVerifier[F])(handleError: Throwable => F[E]): PartialServerEndpoint[SignedJwt, SignedJwt, I, E, O, R, F] =
      endpoint
        .securityIn(jwtAuth)
        .serverSecurityLogic[SignedJwt, F](
          jwtSecurityLogicF[F, E](jwtVerifier, handleError)
        )

    def jwtSecurity[F[_] : Sync](jwtVerifier: JwtVerifier[F])(handleError: Throwable => E): PartialServerEndpoint[SignedJwt, SignedJwt, I, E, O, R, F] =
      endpoint
        .securityIn(jwtAuth)
        .serverSecurityLogic[SignedJwt, F](
          jwtSecurityLogic[F, E](jwtVerifier, handleError)
        )
  }
}
