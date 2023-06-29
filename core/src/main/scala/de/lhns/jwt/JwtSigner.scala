package de.lhns.jwt

import de.lhns.jwt.Jwt.SignedJwt

trait JwtSigner[F[_], -Algorithm <: JwtAlgorithm] {
  type Key

  def sign(jwt: Jwt, algorithm: Algorithm, key: Key): F[SignedJwt]
}
