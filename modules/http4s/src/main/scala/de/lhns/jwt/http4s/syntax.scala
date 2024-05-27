package de.lhns.jwt.http4s

import cats.data.OptionT
import de.lhns.jwt.SignedJwt
import org.http4s.Credentials.Token
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, Request}

object syntax {
  implicit class RequestOps[F[_]](val self: Request[F]) extends AnyVal {
    def jwt: Option[Either[Throwable, SignedJwt]] =
      self.headers.get[Authorization] match {
        case Some(Authorization(Token(AuthScheme.Bearer, token))) =>
          Some(SignedJwt.decode(token))

        case _ =>
          None
      }

    def withJwt(signedJwt: SignedJwt): self.Self =
      self.putHeaders(Authorization(Token(AuthScheme.Bearer, signedJwt.encode)))
  }
}
