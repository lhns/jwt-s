organization := "de.lolhens"
name := "http4s-jwt-auth"
version := "0.0.1-SNAPSHOT"

licenses += ("Apache-2.0", url("https://www.apache.org/licenses/LICENSE-2.0"))

homepage := Some(url("https://github.com/LolHens/http4s-jwt-auth"))
scmInfo := Some(
  ScmInfo(
    url("https://github.com/LolHens/http4s-jwt-auth"),
    "scm:git@github.com:LolHens/http4s-jwt-auth.git"
  )
)
developers := List(
  Developer(id = "LolHens", name = "Pierre Kisters", email = "pierrekisters@gmail.com", url = url("https://github.com/LolHens/"))
)

scalaVersion := "2.13.5"
crossScalaVersions := Seq("2.12.12", scalaVersion.value)

libraryDependencies ++= Seq(
  "com.typesafe.scala-logging" %% "scala-logging" % "3.9.2",
  "org.http4s" %% "http4s-blaze-server" % "0.21.20",
  "com.pauldijou" %% "jwt-circe" % "5.0.0",
)

addCompilerPlugin("com.olegpy" %% "better-monadic-for" % "0.3.1")

Compile / doc / sources := Seq.empty

version := {
  val tagPrefix = "refs/tags/"
  sys.env.get("CI_VERSION").filter(_.startsWith(tagPrefix)).map(_.drop(tagPrefix.length)).getOrElse(version.value)
}

publishMavenStyle := true

publishTo := sonatypePublishToBundle.value

credentials ++= (for {
  username <- sys.env.get("SONATYPE_USERNAME")
  password <- sys.env.get("SONATYPE_PASSWORD")
} yield Credentials(
  "Sonatype Nexus Repository Manager",
  "oss.sonatype.org",
  username,
  password
)).toList
