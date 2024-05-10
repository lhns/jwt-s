package de.lhns.jwt.http4s.middleware

import cats.Monad
import cats.data.{EitherT, Kleisli, OptionT}
import cats.syntax.all._
import de.lhns.jwt.http4s.syntax._
import de.lhns.jwt.{JwtVerifier, SignedJwt}
import org.http4s.Request
import org.http4s.server.{AuthMiddleware, ContextMiddleware}

object JwtMiddleware {
  def apply[F[_] : Monad](
                           jwtVerifier: JwtVerifier[F],
                           onFailure: Option[Throwable] => F[Unit]
                         ): AuthMiddleware[F, SignedJwt] =
    AuthMiddleware(Kleisli { request =>
      OptionT(verifiedJwt(request, jwtVerifier).flatMap {
        case None =>
          onFailure(None)
            .as(None)

        case Some(Left(error)) =>
          onFailure(Some(error))
            .as(None)

        case Some(Right(jwt)) =>
          Monad[F].pure(Some(jwt))
      })
    })

  def context[F[_] : Monad](jwtVerifier: JwtVerifier[F]): ContextMiddleware[F, Option[Either[Throwable, SignedJwt]]] =
    ContextMiddleware(Kleisli { request =>
      OptionT(verifiedJwt(request, jwtVerifier))
    })

  private def verifiedJwt[F[_] : Monad](
                                         request: Request[F],
                                         jwtVerifier: JwtVerifier[F]
                                       ): F[Option[Either[Throwable, SignedJwt]]] =
    request.jwt.map(
      EitherT.fromEither[F](_)
        .flatMapF(jwt => jwt.verify(jwtVerifier).map(_.as(jwt)))
        .value
    ).sequence
}
