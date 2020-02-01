module github.com/dacut/awssig

go 1.13

require (
	github.com/dacut/awssig/timeutil v0.0.0-00010101000000-000000000000
	github.com/palantir/stacktrace v0.0.0-20161112013806-78658fd2d177
	github.com/stretchr/testify v1.4.0 // indirect
	golang.org/x/text v0.3.2
)

replace github.com/dacut/awssig/timeutil => ./timeutil
