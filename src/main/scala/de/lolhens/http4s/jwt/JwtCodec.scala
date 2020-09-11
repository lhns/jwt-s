package de.lolhens.http4s.jwt

import java.time.Clock

import io.circe.Json
import io.circe.jawn.{parse => jawnParse}
import io.circe.syntax._
import pdi.jwt.algorithms.{JwtAsymmetricAlgorithm, JwtHmacAlgorithm}
import pdi.jwt.exceptions.JwtLengthException
import pdi.jwt.{Jwt => _, _}

import scala.concurrent.Promise
import scala.util.Try

class JwtCodec(override val clock: Clock) extends JwtCirceParser[JwtHeader, JwtClaim] {

  import JwtCodec.{parseClaimHelp, parseHeaderHelp}

  override protected def parseHeader(header: String): JwtHeader = parseHeaderHelp(header)(clock)

  override protected def parseClaim(claim: String): JwtClaim = parseClaimHelp(claim)(clock)

  override protected def parse(value: String): Json = jawnParse(value).toTry.get

  override def validateHmacAlgorithm(algorithm: JwtHmacAlgorithm, algorithms: Seq[JwtHmacAlgorithm]): Boolean =
    super.validateHmacAlgorithm(algorithm, algorithms)

  override def validateAsymmetricAlgorithm(algorithm: JwtAsymmetricAlgorithm, algorithms: Seq[JwtAsymmetricAlgorithm]): Boolean =
    super.validateAsymmetricAlgorithm(algorithm, algorithms)

  /**
   * @return a tuple of (header64, header, claim64, claim, signature or empty string if none)
   * @throws JwtLengthException if there is not 2 or 3 parts in the token
   */
  protected def splitToken(token: String): (String, String, String, String, String) = {
    val parts = token.split("\\.")

    val signature = parts.length match {
      case 2 => ""
      case 3 => parts(2)
      case _ => throw new JwtLengthException(s"Expected token [$token] to be composed of 2 or 3 parts separated by dots.")
    }

    (parts(0), JwtBase64.decodeString(parts(0)), parts(1), JwtBase64.decodeString(parts(1)), signature)
  }

  def decodeAllAndVerify[A](token: String,
                            options: JwtOptions,
                            verify: Jwt[JwtAlgorithm] => Option[A]): Try[A] = Try {
    val (header64, header, claim64, claim, signature) = splitToken(token)
    val h = parseHeader(header)
    val c = parseClaim(claim)
    val result = Promise[A]
    validate(header64, h, claim64, c, signature, options, { (data, signature, algorithm) =>
      val jwt = Jwt(algorithm, h, c, data, signature)
      verify(jwt) match {
        case Some(e) =>
          result.success(e)
          true

        case None =>
          false
      }
    })
    result.future.value.get.get
  }
}

object JwtCodec extends JwtCodec(Clock.systemUTC) {
  def apply(clock: Clock): JwtCodec = new JwtCodec(clock)

  private def parseHeaderHelp(header: String)(implicit clock: Clock): JwtHeader = {
    val cursor = parse(header).hcursor
    JwtHeader(
      algorithm = getAlg(cursor)
      , typ = cursor.get[String]("typ").toOption
      , contentType = cursor.get[String]("cty").toOption
      , keyId = cursor.get[String]("kid").toOption
    )
  }

  private def parseClaimHelp(claim: String)(implicit clock: Clock): JwtClaim = {
    val cursor = parse(claim).hcursor
    val contentCursor = List("iss", "sub", "aud", "exp", "nbf", "iat", "jti").foldLeft(cursor) { (cursor, field) =>
      cursor.downField(field).delete.success match {
        case Some(newCursor) => newCursor
        case None => cursor
      }
    }
    JwtClaim(
      content = contentCursor.top.asJson.noSpaces
      , issuer = cursor.get[String]("iss").toOption
      , subject = cursor.get[String]("sub").toOption
      , audience = cursor.get[Set[String]]("aud").orElse(cursor.get[String]("aud").map(s => Set(s))).toOption
      , expiration = cursor.get[Long]("exp").toOption
      , notBefore = cursor.get[Long]("nbf").toOption
      , issuedAt = cursor.get[Long]("iat").toOption
      , jwtId = cursor.get[String]("jti").toOption
    )
  }
}
