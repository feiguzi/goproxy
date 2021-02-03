module github.com/elazarl/goproxy

go 1.15

require (
	github.com/elazarl/goproxy/ext v0.0.0-20190711103511-473e67f1d7d2
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777
)

replace (
	github.com/elazarl/goproxy => ./
	github.com/elazarl/goproxy/ext => ./ext
)
