organization := "de.lolhens"
name := "http4s-jwt-auth"
version := {
  val Tag = "refs/tags/(.*)".r
  sys.env.get("CI_VERSION").collect { case Tag(tag) => tag }
    .getOrElse("0.0.1-SNAPSHOT")
}

scalaVersion := "2.13.8"
crossScalaVersions := Seq("2.12.17", scalaVersion.value)

ThisBuild / versionScheme := Some("early-semver")

licenses += ("Apache-2.0", url("https://www.apache.org/licenses/LICENSE-2.0"))

homepage := scmInfo.value.map(_.browseUrl)
scmInfo := Some(
  ScmInfo(
    url("https://github.com/LolHens/http4s-jwt-auth"),
    "scm:git@github.com:LolHens/http4s-jwt-auth.git"
  )
)
developers := List(
  Developer(id = "LolHens", name = "Pierre Kisters", email = "pierrekisters@gmail.com", url = url("https://github.com/LolHens/"))
)

libraryDependencies ++= Seq(
  "com.typesafe.scala-logging" %% "scala-logging" % "3.9.5",
  "org.http4s" %% "http4s-server" % "0.23.15",
  "com.github.jwt-scala" %% "jwt-circe" % "9.1.1",
)

addCompilerPlugin("com.olegpy" %% "better-monadic-for" % "0.3.1")

Compile / doc / sources := Seq.empty

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
