// This CI-only peer exercises the pinned upstream implementation. It is not
// linked into Aerion or distributed with the production core.
package main

import (
    "encoding/binary"
    "flag"
    "fmt"
    "io"
    "net"
    "os"
    "strconv"
    "time"

    "github.com/SUDOKU-ASCII/sudoku/internal/config"
    "github.com/SUDOKU-ASCII/sudoku/internal/tunnel"
    "github.com/SUDOKU-ASCII/sudoku/pkg/obfs/sudoku"
)

func main() {
    must(os.Setenv("SUDOKU_LOG_LEVEL", "error"))
    mode := flag.String("mode", "server", "server or client")
    addr := flag.String("addr", "127.0.0.1:0", "listen or connect address")
    target := flag.String("target", "", "TCP destination")
    key := flag.String("key", "interop-user-psk", "PSK")
    aead := flag.String("aead", "chacha20-poly1305", "AEAD")
    ascii := flag.String("ascii", "prefer_entropy", "appearance")
    custom := flag.String("custom", "", "custom layout")
    pure := flag.Bool("pure", false, "classic downlink")
    flag.Parse()
    cfg := &config.Config{Key:*key, AEAD:*aead, ASCII:*ascii, PaddingMin:5, PaddingMax:15, EnablePureDownlink:*pure}
    cfg.HTTPMask.Disable = true
    table, err := sudoku.NewTableWithCustom(*key, *ascii, *custom)
    must(err)
    if *mode == "server" {
        listener, err := net.Listen("tcp", *addr)
        must(err)
        fmt.Println(listener.Addr())
        for {
            raw, err := listener.Accept()
            must(err)
            go func() {
                defer raw.Close()
                conn, _, err := tunnel.HandshakeAndUpgradeWithTablesMeta(raw, cfg, []*sudoku.Table{table})
                if err != nil { fmt.Fprintln(os.Stderr, err); return }
                defer conn.Close()
                if _, err = tunnel.ReadKIPMessage(conn); err != nil { fmt.Fprintln(os.Stderr, err); return }
                _, err = io.Copy(conn, conn)
                if err != nil { fmt.Fprintln(os.Stderr, err) }
            }()
        }
    }
    raw, err := net.DialTimeout("tcp", *addr, 10*time.Second)
    must(err)
    defer raw.Close()
    must(raw.SetDeadline(time.Now().Add(15*time.Second)))
    conn, err := tunnel.ClientHandshakeWithUplinkMode(raw, cfg, table, nil, tunnel.ObfsUplinkPure, table.Hint(), true)
    must(err)
    defer conn.Close()
    host, port, err := net.SplitHostPort(*target)
    must(err)
    p, err := strconv.Atoi(port)
    must(err)
    ip := net.ParseIP(host).To4()
    if ip == nil { panic("test destination must be IPv4") }
    address := append([]byte{1}, ip...)
    address = binary.BigEndian.AppendUint16(address, uint16(p))
    must(tunnel.WriteKIPMessage(conn, tunnel.KIPTypeOpenTCP, address))
    payload, err := io.ReadAll(os.Stdin)
    must(err)
    _, err = conn.Write(payload)
    must(err)
    response := make([]byte,len(payload))
    _, err = io.ReadFull(conn,response)
    must(err)
    _, err = os.Stdout.Write(response)
    must(err)
}

func must(err error) { if err != nil { panic(err) } }
