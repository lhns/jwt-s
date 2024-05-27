package de.lhns.jwt

import cats.effect.Sync

sealed trait JwtSigner[F[_]] {
  def sign(jwt: Jwt): F[SignedJwt]
}

object JwtSigner {
  def apply[F[_]](signer: Jwt => F[SignedJwt]): JwtSigner[F] = new JwtSigner[F] {
    override def sign(jwt: Jwt): F[SignedJwt] =
      signer(jwt)
  }

  def delay[F[_] : Sync](signer: Jwt => SignedJwt): JwtSigner[F] = new JwtSigner[F] {
    override def sign(jwt: Jwt): F[SignedJwt] =
      Sync[F].delay(signer(jwt))
  }
}
