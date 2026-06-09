package hysteria2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta1 "github.com/sagernet/sing-quic/congestion_meta1"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing-quic/hysteria"
	hyCC "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"
)

type ServiceOptions struct {
	Context               context.Context
	Logger                logger.Logger
	BrutalDebug           bool
	SendBPS               uint64
	ReceiveBPS            uint64
	IgnoreClientBandwidth bool
	SalamanderPassword    string
	TLSConfig             aTLS.ServerConfig
	UDPDisabled           bool
	UDPTimeout            time.Duration
	Handler               ServerHandler
	MasqueradeHandler     http.Handler
}

type ServerHandler interface {
	N.TCPConnectionHandlerEx
	N.UDPConnectionHandlerEx
}

type Service[U comparable] struct {
	ctx                   context.Context
	logger                logger.Logger
	brutalDebug           bool
	sendBPS               uint64
	receiveBPS            uint64
	ignoreClientBandwidth bool
	salamanderPassword    string
	tlsConfig             aTLS.ServerConfig
	quicConfig            *quic.Config
	usersMu               sync.RWMutex
	userMap               map[string]U // password -> user
	userPwMap             map[U]string // user -> password (reverse index for incremental updates)
	udpDisabled           bool
	udpTimeout            time.Duration
	handler               ServerHandler
	masqueradeHandler     http.Handler
	quicListener          io.Closer
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                !options.UDPDisabled,
		MaxIncomingStreams:             1 << 60,
		InitialStreamReceiveWindow:     hysteria.DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         hysteria.DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: hysteria.DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     hysteria.DefaultConnReceiveWindow,
		MaxIdleTimeout:                 hysteria.DefaultMaxIdleTimeout,
		KeepAlivePeriod:                hysteria.DefaultKeepAlivePeriod,
		DisablePathManager:             true,
	}
	if options.MasqueradeHandler == nil {
		options.MasqueradeHandler = http.NotFoundHandler()
	}
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	return &Service[U]{
		ctx:                   options.Context,
		logger:                options.Logger,
		brutalDebug:           options.BrutalDebug,
		sendBPS:               options.SendBPS,
		receiveBPS:            options.ReceiveBPS,
		ignoreClientBandwidth: options.IgnoreClientBandwidth,
		salamanderPassword:    options.SalamanderPassword,
		tlsConfig:             options.TLSConfig,
		quicConfig:            quicConfig,
		userMap:               make(map[string]U),
		userPwMap:             make(map[U]string),
		udpDisabled:           options.UDPDisabled,
		udpTimeout:            options.UDPTimeout,
		handler:               options.Handler,
		masqueradeHandler:     options.MasqueradeHandler,
	}, nil
}

// UpdateUsers atomically replaces the entire user set. Equivalent to
// removing every current user and re-adding the given list. Kept for
// callers that rebuild a full user list each refresh cycle; new callers
// may prefer AddUsers/RemoveUsers for incremental updates.
//
// Unlike upstream, the swap is performed under usersMu so it is safe to
// call at runtime concurrently with the authentication read path
// (ServeHTTP). Upstream sing-box only calls this once at construction;
// SingR refreshes users live, which would otherwise race on userMap.
func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	userMap := make(map[string]U, len(userList))
	userPwMap := make(map[U]string, len(userList))
	for i, user := range userList {
		userMap[passwordList[i]] = user
		userPwMap[user] = passwordList[i]
	}
	s.usersMu.Lock()
	s.userMap = userMap
	s.userPwMap = userPwMap
	s.usersMu.Unlock()
}

// AddUsers adds or updates users incrementally. If a user already exists
// its password is rotated (old password entry removed first); if a
// password was previously bound to a different user that stale reverse
// entry is dropped. Safe to call concurrently with authentication.
func (s *Service[U]) AddUsers(userList []U, passwordList []string) {
	if len(userList) == 0 {
		return
	}
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	for i, user := range userList {
		password := passwordList[i]
		if oldPassword, ok := s.userPwMap[user]; ok && oldPassword != password {
			delete(s.userMap, oldPassword)
		}
		if oldUser, ok := s.userMap[password]; ok && oldUser != user {
			delete(s.userPwMap, oldUser)
		}
		s.userMap[password] = user
		s.userPwMap[user] = password
	}
}

// RemoveUsers removes users by their identity (U). Unknown users are
// silently ignored. Safe to call concurrently with authentication.
func (s *Service[U]) RemoveUsers(userList []U) {
	if len(userList) == 0 {
		return
	}
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	for _, user := range userList {
		if password, ok := s.userPwMap[user]; ok {
			delete(s.userMap, password)
			delete(s.userPwMap, user)
		}
	}
}

// authenticate looks up a user by the client-supplied auth password under
// a read lock.
func (s *Service[U]) authenticate(password string) (U, bool) {
	s.usersMu.RLock()
	user, loaded := s.userMap[password]
	s.usersMu.RUnlock()
	return user, loaded
}

func (s *Service[U]) Start(conn net.PacketConn) error {
	if s.salamanderPassword != "" {
		conn = NewSalamanderConn(conn, []byte(s.salamanderPassword))
	}
	err := qtls.ConfigureHTTP3(s.tlsConfig)
	if err != nil {
		return err
	}
	listener, err := qtls.Listen(conn, s.tlsConfig, s.quicConfig)
	if err != nil {
		return err
	}
	s.quicListener = listener
	go s.loopConnections(listener)
	return nil
}

func (s *Service[U]) Close() error {
	return common.Close(
		s.quicListener,
	)
}

func (s *Service[U]) loopConnections(listener qtls.Listener) {
	for {
		connection, err := listener.Accept(s.ctx)
		if err != nil {
			if E.IsClosedOrCanceled(err) || errors.Is(err, quic.ErrServerClosed) {
				s.logger.Debug(E.Cause(err, "listener closed"))
			} else {
				s.logger.Error(E.Cause(err, "listener closed"))
			}
			return
		}
		go s.handleConnection(connection)
	}
}

func (s *Service[U]) handleConnection(connection *quic.Conn) {
	session := &serverSession[U]{
		Service:    s,
		ctx:        s.ctx,
		quicConn:   connection,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*udpPacketConn),
	}
	httpServer := http3.Server{
		Handler:          session,
		StreamDispatcher: session.dispatchStream,
	}
	_ = httpServer.ServeQUICConn(connection)
	_ = connection.CloseWithError(0, "")
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx           context.Context
	quicConn      *quic.Conn
	connAccess    sync.Mutex
	connDone      chan struct{}
	connErr       error
	authenticated bool
	authUser      U
	udpAccess     sync.RWMutex
	udpConnMap    map[uint32]*udpPacketConn
}

func (s *serverSession[U]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Host == protocol.URLHost && r.URL.Path == protocol.URLPath {
		if s.authenticated {
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !s.udpDisabled,
				Rx:         s.receiveBPS,
				RxAuto:     s.receiveBPS == 0 && s.ignoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			return
		}
		request := protocol.AuthRequestFromHeader(r.Header)
		user, loaded := s.authenticate(request.Auth)
		if !loaded {
			s.masqueradeHandler.ServeHTTP(w, r)
			return
		}
		s.authUser = user
		s.authenticated = true
		var rxAuto bool
		if s.receiveBPS > 0 && s.ignoreClientBandwidth && request.Rx == 0 {
			s.logger.Debug("process connection from ", r.RemoteAddr, ": BBR disabled by server")
			s.masqueradeHandler.ServeHTTP(w, r)
			return
		} else if !(s.receiveBPS == 0 && s.ignoreClientBandwidth) && request.Rx > 0 {
			rx := request.Rx
			if s.sendBPS > 0 && rx > s.sendBPS {
				rx = s.sendBPS
			}
			s.quicConn.SetCongestionControl(hyCC.NewBrutalSender(rx, s.brutalDebug, s.logger))
		} else {
			timeFunc := ntp.TimeFuncFromContext(s.ctx)
			if timeFunc == nil {
				timeFunc = time.Now
			}
			s.quicConn.SetCongestionControl(congestion_meta2.NewBbrSender(
				congestion_meta2.DefaultClock{TimeFunc: timeFunc},
				congestion.ByteCount(s.quicConn.Config().InitialPacketSize),
				congestion.ByteCount(congestion_meta1.InitialCongestionWindow),
			))
			rxAuto = true
		}
		protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
			UDPEnabled: !s.udpDisabled,
			Rx:         s.receiveBPS,
			RxAuto:     rxAuto,
		})
		w.WriteHeader(protocol.StatusAuthOK)
		if s.ctx.Done() != nil {
			go func() {
				select {
				case <-s.ctx.Done():
					s.closeWithError(s.ctx.Err())
				case <-s.connDone:
				}
			}()
		}
		if !s.udpDisabled {
			go s.loopMessages()
		}
	} else {
		s.masqueradeHandler.ServeHTTP(w, r)
	}
}

func (s *serverSession[U]) dispatchStream(frameType http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	if !s.authenticated || err != nil {
		return false, nil
	}
	if frameType != protocol.FrameTypeTCPRequest {
		return false, nil
	}
	_, err = quicvarint.Read(quicvarint.NewReader(stream))
	if err != nil {
		s.logger.Error(E.Cause(err, "seek frame type"))
		return true, nil
	}
	go func() {
		hErr := s.handleStream(stream)
		if hErr != nil {
			stream.CancelRead(0)
			stream.Close()
			s.logger.Error(E.Cause(hErr, "handle stream request"))
		}
	}()
	return true, nil
}

func (s *serverSession[U]) handleStream(stream *quic.Stream) error {
	destinationString, err := protocol.ReadTCPRequest(stream)
	if err != nil {
		return E.New("read TCP request")
	}
	s.handler.NewConnectionEx(auth.ContextWithUser(s.ctx, s.authUser), &serverConn{Stream: stream}, M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(), M.ParseSocksaddr(destinationString).Unwrap(), nil)
	return nil
}

func (s *serverSession[U]) closeWithError(err error) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	if E.IsClosedOrCanceled(err) {
		s.logger.Debug(E.Cause(err, "connection failed"))
	} else {
		s.logger.Error(E.Cause(err, "connection failed"))
	}
	_ = s.quicConn.CloseWithError(0, "")
}

type serverConn struct {
	*quic.Stream
	responseWritten bool
}

func (c *serverConn) HandshakeFailure(err error) error {
	if c.responseWritten {
		return os.ErrInvalid
	}
	c.responseWritten = true
	buffer := protocol.WriteTCPResponse(false, err.Error(), nil)
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *serverConn) HandshakeSuccess() error {
	if c.responseWritten {
		return nil
	}
	c.responseWritten = true
	buffer := protocol.WriteTCPResponse(true, "", nil)
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	if !c.responseWritten {
		c.responseWritten = true
		buffer := protocol.WriteTCPResponse(true, "", p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return 0, qtls.WrapError(err)
		}
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, qtls.WrapError(err)
}

func (c *serverConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}
