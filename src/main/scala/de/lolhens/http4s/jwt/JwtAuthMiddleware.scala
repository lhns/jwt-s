package de.lolhens.http4s.jwt

import cats.data.{Kleisli, OptionT}
import cats.syntax.either._
import cats.syntax.option._
import de.lolhens.http4s.jwt.JwtAuthMiddleware.logger
import monix.eval.Task
import org.http4s.AuthScheme.Bearer
import org.http4s.Credentials.Token
import org.http4s.headers.Authorization
import org.http4s.server._
import org.http4s.{AuthedRoutes, HttpRoutes, Request}
import org.log4s.getLogger
import pdi.jwt.JwtAlgorithm

class JwtAuthMiddleware[Algorithm <: JwtAlgorithm, A](verifier: JwtVerifier[Algorithm, A],
                                                      options: JwtValidationOptions = JwtValidationOptions.default) {
  private def parseJwt(request: Request[Task]): Either[Option[Throwable], (Jwt[Algorithm], A)] =
    for {
      token <- (for {
        authorization <- request.headers.get(Authorization)
        token <- authorization.credentials match {
          case Token(Bearer, token) => Some(token)
          case _ => None
        }
      } yield token).toRight(None)
      jwt <- verifier.decode(token, options).toEither.leftMap(_.some)
    } yield
      jwt

  val optional: ContextMiddleware[Task, Either[Option[Throwable], (Jwt[Algorithm], A)]] = ContextMiddleware {
    Kleisli(request => OptionT(Task(Some {
      parseJwt(request)
    })))
  }

  val middleware: AuthMiddleware[Task, (Jwt[Algorithm], A)] = AuthMiddleware {
    Kleisli(request => OptionT(Task {
      parseJwt(request) match {
        case Right(result) =>
          Some(result)

        case Left(Some(throwable)) =>
          logger.error(throwable)("JWT authentication failed")
          None

        case Left(None) =>
          None
      }
    }))
  }

  def apply(request: AuthedRoutes[(Jwt[Algorithm], A), Task]): HttpRoutes[Task] =
    middleware(request)
}

object JwtAuthMiddleware {
  private val logger = getLogger("de.lolhens.http4s.jwt-auth")
}
