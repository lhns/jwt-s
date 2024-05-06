package de.lhns.jwt

trait JwtSigner[F[_]] {
  def sign(jwt: Jwt): F[SignedJwt]
}
