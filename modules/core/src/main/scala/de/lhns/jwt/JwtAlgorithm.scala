package de.lhns.jwt

import java.security.{PrivateKey, PublicKey}
import javax.crypto.SecretKey

trait JwtAlgorithm {
  type SignKey
  type VerifyKey

  def name: String
}

object JwtAlgorithm {
  final case class JwtUnknownAlgorithm(name: String) extends JwtAlgorithm {
    override type SignKey = Nothing
    override type VerifyKey = Nothing
  }

  sealed trait JwtAsymmetricAlgorithm extends JwtAlgorithm {
    override type SignKey = PrivateKey
    override type VerifyKey = PublicKey
  }

  object JwtAsymmetricAlgorithm {
    val values: Seq[JwtAsymmetricAlgorithm] =
      JwtRsaAlgorithm.values ++
        JwtEcdsaAlgorithm.values
  }

  sealed trait JwtHmacAlgorithm extends JwtAlgorithm {
    override type SignKey = SecretKey
    override type VerifyKey = SecretKey
  }

  object JwtHmacAlgorithm {
    val values: Seq[JwtHmacAlgorithm] = Seq(
      HS256,
      HS384,
      HS512
    )
  }

  sealed trait JwtRsaAlgorithm extends JwtAsymmetricAlgorithm

  object JwtRsaAlgorithm {
    val values: Seq[JwtRsaAlgorithm] = Seq(
      RS256,
      RS384,
      RS512
    )
  }

  sealed trait JwtEcdsaAlgorithm extends JwtAsymmetricAlgorithm

  object JwtEcdsaAlgorithm {
    val values: Seq[JwtEcdsaAlgorithm] = Seq(
      ES256,
      ES384,
      ES512
    )
  }

  case object HS256 extends JwtHmacAlgorithm {
    val name = "HS256"
  }

  case object HS384 extends JwtHmacAlgorithm {
    val name = "HS384"
  }

  case object HS512 extends JwtHmacAlgorithm {
    val name = "HS512"
  }

  case object RS256 extends JwtRsaAlgorithm {
    val name = "RS256"
  }

  case object RS384 extends JwtRsaAlgorithm {
    val name = "RS384"
  }

  case object RS512 extends JwtRsaAlgorithm {
    val name = "RS512"
  }

  case object ES256 extends JwtEcdsaAlgorithm {
    val name = "ES256"
  }

  case object ES384 extends JwtEcdsaAlgorithm {
    val name = "ES384"
  }

  case object ES512 extends JwtEcdsaAlgorithm {
    val name = "ES512"
  }

  val values: Seq[JwtAlgorithm] =
    JwtHmacAlgorithm.values ++
      JwtAsymmetricAlgorithm.values

  private val valuesByName = values.map(e => e.name -> e).toMap

  def fromString(name: String): Option[JwtAlgorithm] =
    if (name == "none") None
    else Some(valuesByName.getOrElse(name, JwtUnknownAlgorithm(name)))
}
