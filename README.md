bmutil
=======

[![Build Status](https://travis-ci.org/monetas/bmutil.svg)]
(https://travis-ci.org/monetas/bmutil)

Package bmutil provides Bitmessage-specific convenience functions and types.
A comprehensive suite of tests is provided to ensure proper functionality.
Package bmutil is licensed under the liberal ISC license.

This package was developed for bmd, an alternative full-node implementation of
Bitmessage which is under active development by Monetas. Although it was
primarily written for bmd, this package has intentionally been designed so it
can be used as a standalone package for any projects needing the functionality
provided.

It is based off btcutil, which is developed by Conformal.

## Documentation

[![GoDoc](https://godoc.org/github.com/monetas/bmutil?status.png)]
(http://godoc.org/github.com/monetas/bmutil)

Full `go doc` style documentation for the project can be viewed online without
installing this package by using the GoDoc site here:
http://godoc.org/github.com/monetas/bmutil

You can also view the documentation locally once the package is installed with
the `godoc` tool by running `godoc -http=":6060"` and pointing your browser to
http://localhost:6060/pkg/github.com/monetas/bmutil

## Installation

```bash
$ go get github.com/DanielKrawisz/bmutil
```
## License

Package btcutil is licensed under the [copyfree](http://copyfree.org) ISC
License.
