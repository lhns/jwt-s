# jwt-s

[![build](https://github.com/lhns/jwt-s/actions/workflows/build.yml/badge.svg)](https://github.com/lhns/jwt-s/actions/workflows/build.yml)
[![Release Notes](https://img.shields.io/github/release/lhns/jwt-s.svg?maxAge=3600)](https://github.com/lhns/jwt-s/releases/latest)
[![Maven Central](https://img.shields.io/maven-central/v/de.lhns/jwt-s_2.13)](https://search.maven.org/artifact/de.lhns/jwt-s_2.13)
[![Apache License 2.0](https://img.shields.io/github/license/lhns/jwt-s.svg?maxAge=3600)](https://www.apache.org/licenses/LICENSE-2.0)
[![Scala Steward badge](https://img.shields.io/badge/Scala_Steward-helping-blue.svg?style=flat&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAQCAMAAAARSr4IAAAAVFBMVEUAAACHjojlOy5NWlrKzcYRKjGFjIbp293YycuLa3pYY2LSqql4f3pCUFTgSjNodYRmcXUsPD/NTTbjRS+2jomhgnzNc223cGvZS0HaSD0XLjbaSjElhIr+AAAAAXRSTlMAQObYZgAAAHlJREFUCNdNyosOwyAIhWHAQS1Vt7a77/3fcxxdmv0xwmckutAR1nkm4ggbyEcg/wWmlGLDAA3oL50xi6fk5ffZ3E2E3QfZDCcCN2YtbEWZt+Drc6u6rlqv7Uk0LdKqqr5rk2UCRXOk0vmQKGfc94nOJyQjouF9H/wCc9gECEYfONoAAAAASUVORK5CYII=)](https://scala-steward.org)

*previously http4s-jwt-auth*

Simple JWT library for scala with integration for circe and http4s.

### build.sbt
```sbt
libraryDependencies ++= Seq(
  "de.lhns" %% "jwt-s" % "1.0.1",
  "de.lhns" %% "jwt-s-http4s" % "1.0.1",
  "de.lhns" %% "jwt-s-jwt-scala" % "1.0.1"
)
```

## License
This project uses the Apache 2.0 License. See the file called LICENSE.
