lazy val scalaVersions = Seq("3.3.6", "2.13.16")

ThisBuild / scalaVersion := scalaVersions.head
ThisBuild / versionScheme := Some("early-semver")
ThisBuild / organization := "de.lhns"
ThisBuild / version := (core.projectRefs.head / version).value
name := (core.projectRefs.head / name).value

val V = new {
  val betterMonadicFor = "0.3.1"
  val bouncyCastle = "1.81"
  val catsEffect = "3.6.3"
  val circe = "0.14.14"
  val http4s = "0.23.30"
  val jwtScala = "11.0.2"
  val logbackClassic = "1.5.18"
  val munit = "1.1.1"
  val munitCatsEffect = "2.1.0"
  val scalaJavaTime = "2.6.0"
  val scalaLogging = "3.9.5"
  val scodecBits = "1.2.4"
  val tapir = "1.11.40"
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

  sonatypeCredentialHost := Sonatype.sonatypeCentralHost,

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
    .aggregate(moduleTapir.projectRefs: _*)

lazy val core = projectMatrix.in(file("modules/core"))
  .settings(commonSettings)
  .settings(
    name := "jwt-s",

    libraryDependencies ++= Seq(
      "io.circe" %%% "circe-generic" % V.circe,
      "io.circe" %%% "circe-parser" % V.circe,
      "org.scodec" %%% "scodec-bits" % V.scodecBits,
      "org.typelevel" %%% "cats-effect" % V.catsEffect,
    ),
  )
  .jvmPlatform(scalaVersions)
  .jsPlatform(
    scalaVersions,
    libraryDependencies ++= Seq(
      "io.github.cquiroz" %%% "scala-java-time" % V.scalaJavaTime % Test,
      "io.github.cquiroz" %%% "scala-java-time-tzdb" % V.scalaJavaTime % Test,
    )
  )

lazy val moduleJwtScala = projectMatrix.in(file("modules/jwt-scala"))
  .dependsOn(core % "compile->compile;test->test")
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
  .dependsOn(core % "compile->compile;test->test")
  .settings(commonSettings)
  .settings(
    name := "jwt-s-http4s",

    libraryDependencies ++= Seq(
      "org.http4s" %%% "http4s-server" % V.http4s,
    ),
  )
  .jvmPlatform(scalaVersions)
  .jsPlatform(scalaVersions)

lazy val moduleTapir = projectMatrix.in(file("modules/tapir"))
  .dependsOn(core % "compile->compile;test->test")
  .settings(commonSettings)
  .settings(
    name := "jwt-s-tapir",

    libraryDependencies ++= Seq(
      "com.softwaremill.sttp.tapir" %%% "tapir-core" % V.tapir,
    ),
  )
  .jvmPlatform(
    scalaVersions,
    libraryDependencies ++= Seq(
      "com.softwaremill.sttp.tapir" %% "tapir-http4s-server" % V.tapir % Test,
    )
  )
  .jsPlatform(scalaVersions)
