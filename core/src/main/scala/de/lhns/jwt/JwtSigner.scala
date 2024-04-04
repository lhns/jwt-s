package de.lhns.jwt

trait JwtSigner[F[_], -Algorithm <: JwtAlgorithm, Key] {
  def sign(jwt: Jwt, algorithm: Algorithm, key: Key): F[SignedJwt]
}
