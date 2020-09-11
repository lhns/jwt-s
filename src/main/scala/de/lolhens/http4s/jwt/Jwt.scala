package de.lolhens.http4s.jwt

import pdi.jwt.{JwtAlgorithm, JwtClaim, JwtHeader}

case class Jwt[Algorithm <: JwtAlgorithm](algorithm: Algorithm,
                                          header: JwtHeader,
                                          claim: JwtClaim,
                                          data: Array[Byte],
                                          signature: Array[Byte])
