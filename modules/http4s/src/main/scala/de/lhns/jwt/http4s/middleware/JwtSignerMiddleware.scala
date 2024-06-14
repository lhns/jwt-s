package de.lhns.jwt.http4s.middleware

import cats.Monad
import cats.data.OptionT
import de.lhns.jwt.http4s.syntax._
import de.lhns.jwt.{Jwt, JwtSigner}
import org.http4s.{ContextRequest, ContextRoutes, HttpRoutes}

object JwtSignerMiddleware {
  def apply[F[_] : Monad](signer: JwtSigner[F]): HttpRoutes[F] => ContextRoutes[Jwt, F] = { routes =>
    ContextRoutes[Jwt, F] { case ContextRequest(jwt, request) =>
      OptionT.liftF(signer.sign(jwt)).flatMap { signedJwt =>
        routes(request.withJwt(signedJwt))
      }
    }
  }
}
