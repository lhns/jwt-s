lazy val scalaVersions = Seq("3.3.3", "2.13.14")

ThisBuild / scalaVersion := scalaVersions.head
ThisBuild / versionScheme := Some("early-semver")
ThisBuild / organization := "de.lhns"
name := (core.projectRefs.head / name).value

val V = new {
  val betterMonadicFor = "0.3.1"
  val bouncyCastle = "1.78.1"
  val catsEffect = "3.5.4"
  val circe = "0.14.9"
  val http4s = "0.23.27"
  val jwtScala = "10.0.1"
  val logbackClassic = "1.5.6"
  val munit = "1.0.0"
  val munitCatsEffect = "2.0.0"
  val scalaLogging = "3.9.5"
}

lazy val commonSettings: SettingsDefinition = Def.settings(
  version := {
    val Tag = "refs/tags/v?([0-9]+(?:\\.[0-9]+)+(?:[+-].*)?)".r
    sys.env.get("CI_VERSION").collect { case Tag(tag) => tag }
      .getOrElse("0.0.1-SNAPSHOT")
  },

  licenses += ("Apache-2.0", url("https://www.apache.org/licenses/LICENSE-2.0")),

  homepage := scmInfo.value.map(_.browseUrl),
  scmInfo := Some(
    ScmInfo(
      url("https://github.com/lhns/jwt-s"),
      "scm:git@github.com:lhns/jwt-s.git"
    )
  ),
  developers := List(
    Developer(id = "lhns", name = "Pierre Kisters", email = "pierrekisters@gmail.com", url = url("https://github.com/lhns/"))
  ),

  libraryDependencies ++= Seq(
    "ch.qos.logback" % "logback-classic" % V.logbackClassic % Test,
    "org.typelevel" %%% "munit-cats-effect" % V.munitCatsEffect % Test,
    "org.scalameta" %%% "munit" % V.munit % Test,
  ),

  testFrameworks += new TestFramework("munit.Framework"),

  libraryDependencies ++= virtualAxes.?.value.getOrElse(Seq.empty).collectFirst {
    case VirtualAxis.ScalaVersionAxis(version, _) if version.startsWith("2.") =>
      compilerPlugin("com.olegpy" %% "better-monadic-for" % V.betterMonadicFor)
  },

  Compile / doc / sources := Seq.empty,

  publishMavenStyle := true,

  publishTo := sonatypePublishToBundle.value,

  sonatypeCredentialHost := "s01.oss.sonatype.org",

  credentials ++= (for {
    username <- sys.env.get("SONATYPE_USERNAME")
    password <- sys.env.get("SONATYPE_PASSWORD")
  } yield Credentials(
    "Sonatype Nexus Repository Manager",
    sonatypeCredentialHost.value,
    username,
    password
  )).toList
)

lazy val root: Project =
  project
    .in(file("."))
    .settings(commonSettings)
    .settings(
      publishArtifact := false,
      publish / skip := true
    )
    .aggregate(core.projectRefs: _*)
    .aggregate(moduleJwtScala.projectRefs: _*)
    .aggregate(moduleHttp4s.projectRefs: _*)

lazy val core = projectMatrix.in(file("modules/core"))
  .settings(commonSettings)
  .settings(
    name := "jwt-s",

    libraryDependencies ++= Seq(
      "io.circe" %%% "circe-generic" % V.circe,
      "io.circe" %%% "circe-parser" % V.circe,
      "org.typelevel" %%% "cats-effect" % V.catsEffect,
    ),
  )
  .jvmPlatform(scalaVersions)
  .jsPlatform(scalaVersions)

lazy val moduleJwtScala = projectMatrix.in(file("modules/jwt-scala"))
  .dependsOn(core)
  .settings(commonSettings)
  .settings(
    name := "jwt-s-jwt-scala",

    libraryDependencies ++= Seq(
      "com.github.jwt-scala" %% "jwt-core" % V.jwtScala,
      "org.bouncycastle" % "bcpkix-jdk18on" % V.bouncyCastle % Test,
    ),
  )
  .jvmPlatform(scalaVersions)

lazy val moduleHttp4s = projectMatrix.in(file("modules/http4s"))
  .dependsOn(core)
  .settings(commonSettings)
  .settings(
    name := "jwt-s-http4s",

    libraryDependencies ++= Seq(
      "org.http4s" %%% "http4s-server" % V.http4s,
    ),
  )
  .jvmPlatform(scalaVersions)
  .jsPlatform(scalaVersions)
