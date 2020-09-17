package de.lolhens.http4s.jwt

import pdi.jwt.{JwtAlgorithm, JwtClaim, JwtHeader}

case class Jwt[+Algorithm <: JwtAlgorithm](header: JwtHeader,
                                           claim: JwtClaim,
                                           data: Array[Byte],
                                           signature: Array[Byte]) {
  def algorithm: Option[Algorithm] = header.algorithm match {
    case Some(algorithm) => Some(algorithm.asInstanceOf[Algorithm])
    case None => None
  }
}
