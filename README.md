# JWT Playground

Use this server for testing `HS256` signed JWT tokens. I wrote it while trying
to figure out why I couldn't verify an `id_token` passed to me by a web app that
authenticated itself via Auth0.

I'd make the algorithm configurable eventually but for now, to use a different
signing algorithm you'd need to modify the code itself.
