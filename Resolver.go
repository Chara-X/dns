package dns

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/miekg/dns"
)

type Resolver struct {
	Addr string
	NS   string
}

func (r *Resolver) ListenAndServe() error {
	var l, _ = net.Listen("tcp", r.Addr)
	for {
		var conn, _ = l.Accept()
		go func() {
			defer conn.Close()
			var length uint16
			binary.Read(conn, binary.BigEndian, &length)
			var request = make([]byte, length)
			io.ReadFull(conn, request)
			var req = new(dns.Msg)
			fmt.Println(req.Unpack(request))
			var rep = new(dns.Msg)
			rep.SetReply(req)
			rep.Authoritative = true
			for _, question := range req.Question {
				rep.Answer = append(rep.Answer, []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: r.Resolve(question.Name)}}...)
			}
			var reply, _ = rep.Pack()
			binary.Write(conn, binary.BigEndian, uint16(len(reply)))
			conn.Write(reply)
		}()
	}
}
func (r *Resolver) Resolve(name string) net.IP {
	var ns = net.ParseIP(r.NS)
	for {
		fmt.Printf("ns: @%s\tname: %s\n", ns.String(), name)
		var request = new(dns.Msg)
		request.SetQuestion(name, dns.TypeA)
		var req, _ = request.Pack()
		var conn, _ = net.Dial("udp", ns.String()+":53")
		conn.Write(req)
		var rep = make([]byte, 512)
		var n, _ = conn.Read(rep)
		var reply = new(dns.Msg)
		reply.Unpack(rep[:n])
		if ip := getAnswer(reply); ip != nil {
			return ip
		} else if nsIP := getExtra(reply); nsIP != nil {
			ns = nsIP
		} else if domain := getNS(reply); domain != "" {
			ns = r.Resolve(domain)
		} else {
			panic("Invalid reply")
		}
	}
}
func getAnswer(reply *dns.Msg) net.IP {
	for _, record := range reply.Answer {
		if record.Header().Rrtype == dns.TypeA {
			fmt.Println("  answer: ", record)
			return record.(*dns.A).A
		}
	}
	return nil
}
func getNS(reply *dns.Msg) string {
	for _, record := range reply.Ns {
		if record.Header().Rrtype == dns.TypeNS {
			fmt.Println("  ns: ", record)
			return record.(*dns.NS).Ns
		}
	}
	return ""
}
func getExtra(reply *dns.Msg) net.IP {
	for _, record := range reply.Extra {
		if record.Header().Rrtype == dns.TypeA {
			fmt.Println("  extra: ", record)
			return record.(*dns.A).A
		}
	}
	return nil
}
