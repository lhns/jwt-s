package de.lolhens.http4s.jwt

import cats.Monad
import cats.data.{EitherT, Kleisli, OptionT}
import cats.syntax.functor._
import cats.syntax.option._
import com.typesafe.scalalogging.Logger
import org.http4s.AuthScheme.Bearer
import org.http4s.Credentials.Token
import org.http4s.headers.Authorization
import org.http4s.server._
import org.http4s.{AuthedRoutes, ContextRequest, HttpRoutes, Request}
import pdi.jwt.JwtAlgorithm

class JwtAuthMiddleware[F[_], Algorithm <: JwtAlgorithm, A](verifier: JwtVerifier[F, Algorithm, A],
                                                            options: JwtValidationOptions = JwtValidationOptions.default)
                                                           (implicit F: Monad[F]) {
  private val logger = Logger[JwtAuthMiddleware[F, Algorithm, A]]

  private def parseJwt(request: Request[F]): F[Either[Option[Throwable], (Jwt[Algorithm], Option[A])]] = {
    (for {
      token <- EitherT.fromOption[F](
        for {
          authorization <- request.headers.get(Authorization)
          token <- authorization.credentials match {
            case Token(Bearer, token) => Some(token)
            case _ => None
          }
        } yield token,
        ifNone = None
      )
      jwt <- EitherT {
        verifier.decode(token, options).map(_.toEither)
      }.leftMap(_.some)
    } yield
      jwt).value
  }

  val optional: ContextMiddleware[F, Either[Option[Throwable], (Jwt[Algorithm], Option[A])]] = ContextMiddleware {
    Kleisli(request => OptionT(parseJwt(request).map(_.some)))
  }

  val middleware: AuthMiddleware[F, (Jwt[Algorithm], Option[A])] = AuthMiddleware {
    Kleisli(request => OptionT(parseJwt(request).map {
      case Right(result) =>
        Some(result)

      case Left(Some(throwable)) =>
        logger.error("JWT authentication failed", throwable)
        None

      case Left(None) =>
        None
    }))
  }

  def apply(request: AuthedRoutes[(Jwt[Algorithm], Option[A]), F]): HttpRoutes[F] =
    middleware(request)

  def flatMap[B](f: ((Jwt[Algorithm], Option[A])) => ContextMiddleware[F, B]): ContextMiddleware[F, B] = { service =>
    middleware(Kleisli {
      case ContextRequest(context, request) =>
        f(context).apply(service).apply(request)
    })
  }
}
