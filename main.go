package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/labstack/echo/v4"
	"github.com/mudkipme/mortis/api"
	"github.com/mudkipme/mortis/server/memos"
)

func main() {
	addr := flag.String("addr", "0.0.0.0", "Listen address")
	port := flag.Int("port", 5231, "Listen port")
	grpcAddr := flag.String("grpc-addr", "127.0.0.1:5230", "gRPC server address")
	flag.Parse()

	server := memos.NewServer(*grpcAddr)

	e := echo.New()

	api.RegisterHandlers(e, server)

	listenAddr := fmt.Sprintf("%s:%d", *addr, *port)
	log.Fatal(e.Start(listenAddr))
}
