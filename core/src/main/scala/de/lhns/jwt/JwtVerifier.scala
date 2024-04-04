package de.lhns.jwt

trait JwtVerifier[F[_], -Algorithm <: JwtAlgorithm, Key] {
  def verify(signedJwt: SignedJwt, algorithm: Algorithm, key: Key, options: JwtValidationOptions): F[Either[Throwable, Jwt]]
}
