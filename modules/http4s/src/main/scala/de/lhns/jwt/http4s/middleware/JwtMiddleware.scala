package de.lhns.jwt.http4s.middleware

import cats.Monad
import cats.data.{Kleisli, OptionT}
import de.lhns.jwt.SignedJwt
import org.http4s.AuthScheme
import org.http4s.Credentials.Token
import org.http4s.headers.Authorization
import org.http4s.server.ContextMiddleware
import cats.syntax.all._
import de.lhns.jwt.http4s.syntax._

object JwtMiddleware {
  def unverified[F[_] : Monad]: ContextMiddleware[F, SignedJwt] =
    ContextMiddleware[F, SignedJwt](Kleisli { request =>
      OptionT.fromOption[F](request.jwt.flatMap(_.toOption))
    })


}
