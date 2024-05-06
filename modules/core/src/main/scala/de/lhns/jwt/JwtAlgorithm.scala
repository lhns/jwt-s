package de.lhns.jwt

sealed abstract class JwtAlgorithm(val name: String)

object JwtAlgorithm {
  final case class JwtUnknownAlgorithm(override val name: String) extends JwtAlgorithm(name)

  sealed abstract class JwtAsymmetricAlgorithm(name: String) extends JwtAlgorithm(name)

  object JwtAsymmetricAlgorithm {
    val values: Seq[JwtAsymmetricAlgorithm] =
      JwtRsaAlgorithm.values ++
        JwtEcdsaAlgorithm.values
  }

  sealed abstract class JwtHmacAlgorithm(name: String) extends JwtAlgorithm(name)

  object JwtHmacAlgorithm {
    val values: Seq[JwtHmacAlgorithm] = Seq(
      HS256,
      HS384,
      HS512
    )
  }

  sealed abstract class JwtRsaAlgorithm(name: String) extends JwtAsymmetricAlgorithm(name)

  object JwtRsaAlgorithm {
    val values: Seq[JwtRsaAlgorithm] = Seq(
      RS256,
      RS384,
      RS512
    )
  }

  sealed abstract class JwtEcdsaAlgorithm(name: String) extends JwtAsymmetricAlgorithm(name)

  object JwtEcdsaAlgorithm {
    val values: Seq[JwtEcdsaAlgorithm] = Seq(
      ES256,
      ES384,
      ES512
    )
  }

  case object HS256 extends JwtHmacAlgorithm("HS256")

  case object HS384 extends JwtHmacAlgorithm("HS384")

  case object HS512 extends JwtHmacAlgorithm("HS512")

  case object RS256 extends JwtRsaAlgorithm("RS256")

  case object RS384 extends JwtRsaAlgorithm("RS384")

  case object RS512 extends JwtRsaAlgorithm("RS512")

  case object ES256 extends JwtEcdsaAlgorithm("ES256")

  case object ES384 extends JwtEcdsaAlgorithm("ES384")

  case object ES512 extends JwtEcdsaAlgorithm("ES512")

  val values: Seq[JwtAlgorithm] =
    JwtHmacAlgorithm.values ++
      JwtAsymmetricAlgorithm.values

  private val valuesByName = values.map(e => e.name -> e).toMap

  def fromString(name: String): Option[JwtAlgorithm] =
    if (name == "none") None
    else Some(valuesByName.getOrElse(name, JwtUnknownAlgorithm(name)))

  def toString(algorithm: Option[JwtAlgorithm]): String =
    algorithm.fold("none")(_.name)
}
