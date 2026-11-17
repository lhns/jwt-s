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
  "de.lhns" %% "jwt-s" % "2.1.0",
  "de.lhns" %% "jwt-s-http4s" % "2.1.0",
  "de.lhns" %% "jwt-s-tapir" % "2.1.0",
  "de.lhns" %% "jwt-s-jwt-scala" % "2.1.0"
)
```

## Certificate chain (x5c) verification

`certPathVerifier` validates the `x5c` header chain against a trust store and verifies the signature with the leaf's key.

- Use a dedicated trust store containing only your own CA. Never use the JVM default `cacerts`: anyone holding a publicly trusted TLS certificate could then mint tokens.
- Restrict the accepted leaf certificate with `setTargetCertConstraints`, otherwise any certificate issued by a trusted CA is accepted:

```scala
import java.security.cert.X509CertSelector

val verifier = JwtScala.certPathVerifier[IO](
  keyStore,
  pkixParameters = { p =>
    p.setRevocationEnabled(false)
    val selector = new X509CertSelector()
    selector.setSubject("CN=my-issuer,O=Example")
    p.setTargetCertConstraints(selector)
  }
)
```

- Revocation checking is off by default (`defaultPkixParameters`). Enable it with `p.setRevocationEnabled(true)` (and configure CRL/OCSP as needed); note that it may perform blocking network I/O.

## Loading keys and certificates

`JwtKeys` loads keys and certificates from PEM or DER bytes and returns `Either[Throwable, _]`:

```scala
import de.lhns.jwt.JwtKeys
import java.nio.file.{Files, Paths}

val privateKey = JwtKeys.privateKey(Files.readAllBytes(Paths.get("key.pem")))
val certPath = JwtKeys.certPath(Files.readAllBytes(Paths.get("chain.pem")))
val trustStore = JwtKeys.trustStore(Files.readAllBytes(Paths.get("ca.pem")))
```

- Private keys must be unencrypted PKCS#8 (`BEGIN PRIVATE KEY`, RSA or EC). Convert others with `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem`.
- `certPath` and `trustStore` take certificates only (a file that also contains a private key block is rejected).
- `certPath` keeps the input order: put the leaf certificate first.
- `trustStore` puts every certificate of the input into a new in-memory store for `certPathVerifier`; empty input is an error. It trusts every certificate in the input, a leaf included, so pass CA certificates only.

## License
This project uses the Apache 2.0 License. See the file called LICENSE.
