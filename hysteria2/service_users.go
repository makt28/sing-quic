package hysteria2

import "sync"

// This file is a fork addition (github.com/makt28/sing-quic) and has no
// upstream counterpart.
//
// Upstream sing-quic keeps a bare `userMap map[string]U` on Service, writes
// it without a lock, and only ever calls UpdateUsers once at construction.
// SingR refreshes the user list live from a panel, so the authentication
// read path races that write; a full map rebuild per refresh cycle is also
// wasteful at 2000-user scale, hence the incremental AddUsers/RemoveUsers.
//
// The logic is deliberately isolated here so that resyncing with upstream
// only ever conflicts on the three one-line hooks left in service.go: the
// Service field, its initialization in NewService, and the ServeHTTP
// lookup. Keep it that way.

// userTable maps hysteria2 auth passwords to user identities. All methods
// are safe for concurrent use.
type userTable[U comparable] struct {
	mu         sync.RWMutex
	byPassword map[string]U // password -> user
	byUser     map[U]string // user -> password (reverse index for incremental updates)
}

func newUserTable[U comparable]() *userTable[U] {
	return &userTable[U]{
		byPassword: make(map[string]U),
		byUser:     make(map[U]string),
	}
}

// replace atomically swaps in an entirely new user set.
func (t *userTable[U]) replace(userList []U, passwordList []string) {
	byPassword := make(map[string]U, len(userList))
	byUser := make(map[U]string, len(userList))
	for i, user := range userList {
		byPassword[passwordList[i]] = user
		byUser[user] = passwordList[i]
	}
	t.mu.Lock()
	t.byPassword = byPassword
	t.byUser = byUser
	t.mu.Unlock()
}

// add inserts or updates users. If a user already exists its password is
// rotated (the old password entry is removed first); if a password was
// previously bound to a different user, that stale reverse entry is dropped.
func (t *userTable[U]) add(userList []U, passwordList []string) {
	if len(userList) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, user := range userList {
		password := passwordList[i]
		if oldPassword, ok := t.byUser[user]; ok && oldPassword != password {
			delete(t.byPassword, oldPassword)
		}
		if oldUser, ok := t.byPassword[password]; ok && oldUser != user {
			delete(t.byUser, oldUser)
		}
		t.byPassword[password] = user
		t.byUser[user] = password
	}
}

// remove drops users by their identity. Unknown users are ignored.
func (t *userTable[U]) remove(userList []U) {
	if len(userList) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, user := range userList {
		if password, ok := t.byUser[user]; ok {
			delete(t.byPassword, password)
			delete(t.byUser, user)
		}
	}
}

// lookup resolves the client-supplied auth password to a user.
func (t *userTable[U]) lookup(password string) (U, bool) {
	t.mu.RLock()
	user, loaded := t.byPassword[password]
	t.mu.RUnlock()
	return user, loaded
}

// UpdateUsers atomically replaces the entire user set. Equivalent to
// removing every current user and re-adding the given list. Kept for
// callers that rebuild a full user list each refresh cycle; new callers
// may prefer AddUsers/RemoveUsers for incremental updates.
//
// Unlike upstream, the swap is performed under a lock, so it is safe to
// call at runtime concurrently with the authentication read path.
func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	s.users.replace(userList, passwordList)
}

// AddUsers adds or updates users incrementally, rotating the password of a
// user that already exists. Safe to call concurrently with authentication.
func (s *Service[U]) AddUsers(userList []U, passwordList []string) {
	s.users.add(userList, passwordList)
}

// RemoveUsers removes users by their identity (U). Unknown users are
// silently ignored. Safe to call concurrently with authentication.
func (s *Service[U]) RemoveUsers(userList []U) {
	s.users.remove(userList)
}
