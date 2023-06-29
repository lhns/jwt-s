package de.lhns.jwt

import de.lhns.jwt.Jwt.SignedJwt

trait JwtVerifier[F[_], Algorithm <: JwtAlgorithm] {
  type Key

  def verify(signedJwt: SignedJwt, algorithm: Algorithm, key: Key, options: JwtValidationOptions): F[Either[Throwable, Jwt]]
}
