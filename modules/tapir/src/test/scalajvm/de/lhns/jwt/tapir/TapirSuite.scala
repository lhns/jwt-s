package de.lhns.jwt.tapir

import cats.effect.IO
import de.lhns.jwt.SignedJwt
import de.lhns.jwt.tapir.TapirJwtAuth._
import munit.CatsEffectSuite
import org.http4s.Credentials.Token
import org.http4s.headers.Authorization
import org.http4s.{AuthScheme, Request}
import sttp.tapir._
import sttp.tapir.server.http4s.Http4sServerInterpreter

class TapirSuite extends CatsEffectSuite {
  private val testEndpoint = endpoint
    .get
    .in("")
    .out(stringBody)
    .securityIn(jwtAuth)
    .serverSecurityLogicPure[SignedJwt, IO](jwt => Right(jwt))
    .serverLogicPure(jwt => _ => Right("hello world"))

  def testToken(token: String): IO[String] = {
    val routes = Http4sServerInterpreter[IO].toRoutes(testEndpoint)
    routes(Request[IO]().putHeaders(Authorization(Token(AuthScheme.Bearer, token)))).foldF(IO(""))(_.as[String])
  }

  test("valid token") {
    testToken(
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    ).map { response =>
      assertEquals(response, "hello world")
    }
  }

  test("invalid token") {
    testToken("test").map { response =>
      assertEquals(response, "Invalid value for: header Authorization")
    }
  }
}
