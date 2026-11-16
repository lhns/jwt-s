package de.lhns.jwt

import scala.concurrent.duration.{Duration, FiniteDuration}

case class JwtValidationOptions(
                                 requireAlgorithm: Boolean = true,
                                 requireIssuer: Boolean = false,
                                 requireSubject: Boolean = false,
                                 requireAudience: Boolean = false,
                                 requireExpiration: Boolean = false,
                                 requireNotBefore: Boolean = false,
                                 requireIssuedAt: Boolean = false,
                                 requireJwtId: Boolean = false,
                                 validateExpiration: Boolean = true,
                                 validateNotBefore: Boolean = true,
                                 leeway: FiniteDuration = Duration.Zero,
                                 expectedIssuer: Option[String] = None,
                                 expectedAudience: Option[String] = None,
                                 acceptedTypes: Set[String] = Set("JWT")
                               )

object JwtValidationOptions {
  val default: JwtValidationOptions = JwtValidationOptions()
}
