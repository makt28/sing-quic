package hysteria2

import (
	"strconv"
	"sync"
	"testing"
)

// newUserTestService builds a Service[int] with only the user table
// initialized. NewService requires a full TLS config / QUIC stack which is
// irrelevant to user-table behavior, so the user-management tests
// construct the struct directly (they live in package hysteria2 and can
// reach the unexported fields). Going through Service rather than
// userTable directly also covers the exported delegation methods.
func newUserTestService() *Service[int] {
	return &Service[int]{users: newUserTable[int]()}
}

// assertConsistent verifies the two indexes are exact inverses of each
// other. Must be called with no concurrent mutators in flight.
func assertConsistent(t *testing.T, s *Service[int]) {
	t.Helper()
	tbl := s.users
	if len(tbl.byPassword) != len(tbl.byUser) {
		t.Fatalf("map size mismatch: byPassword=%d byUser=%d", len(tbl.byPassword), len(tbl.byUser))
	}
	for pw, u := range tbl.byPassword {
		if got, ok := tbl.byUser[u]; !ok || got != pw {
			t.Fatalf("byPassword[%q]=%d but byUser[%d]=%q (ok=%v)", pw, u, u, got, ok)
		}
	}
	for u, pw := range tbl.byUser {
		if got, ok := tbl.byPassword[pw]; !ok || got != u {
			t.Fatalf("byUser[%d]=%q but byPassword[%q]=%d (ok=%v)", u, pw, pw, got, ok)
		}
	}
}

// TestServiceUsersConsistency exercises the incremental add/remove logic,
// including password rotation and a password being reassigned to a
// different user, asserting the two indexes stay consistent throughout.
func TestServiceUsersConsistency(t *testing.T) {
	s := newUserTestService()

	s.AddUsers([]int{1, 2}, []string{"a", "b"})
	if u, ok := s.users.lookup("a"); !ok || u != 1 {
		t.Fatalf("lookup(a) = %d,%v; want 1,true", u, ok)
	}
	if u, ok := s.users.lookup("b"); !ok || u != 2 {
		t.Fatalf("lookup(b) = %d,%v; want 2,true", u, ok)
	}
	assertConsistent(t, s)

	// Rotate user 1's password: a -> a2. Old password must stop working.
	s.AddUsers([]int{1}, []string{"a2"})
	if _, ok := s.users.lookup("a"); ok {
		t.Fatal("rotated-away password 'a' still authenticates")
	}
	if u, ok := s.users.lookup("a2"); !ok || u != 1 {
		t.Fatalf("lookup(a2) = %d,%v; want 1,true", u, ok)
	}
	assertConsistent(t, s)

	// Reassign password 'b' (was user 2) to user 3. User 2 should vanish.
	s.AddUsers([]int{3}, []string{"b"})
	if u, ok := s.users.lookup("b"); !ok || u != 3 {
		t.Fatalf("lookup(b) = %d,%v; want 3,true", u, ok)
	}
	if _, ok := s.users.byUser[2]; ok {
		t.Fatal("user 2 still present after its only password was reassigned")
	}
	assertConsistent(t, s)

	// Remove user 1; its current password must stop working.
	s.RemoveUsers([]int{1})
	if _, ok := s.users.lookup("a2"); ok {
		t.Fatal("removed user 1 password still authenticates")
	}
	s.RemoveUsers([]int{999}) // unknown user is a no-op
	assertConsistent(t, s)

	// Full rebuild replaces everything.
	s.UpdateUsers([]int{10, 11}, []string{"x", "y"})
	if _, ok := s.users.lookup("b"); ok {
		t.Fatal("UpdateUsers did not drop previous users")
	}
	if u, ok := s.users.lookup("x"); !ok || u != 10 {
		t.Fatalf("lookup(x) = %d,%v; want 10,true", u, ok)
	}
	assertConsistent(t, s)
}

// TestServiceUsersConcurrent hammers the user-table mutators against the
// authentication read path concurrently. Its real purpose is to be run
// under the race detector:
//
//	go test -race -run TestServiceUsersConcurrent ./hysteria2/
//
// It guards userTable's lock against being dropped on a future upstream
// resync — upstream writes its user map without a lock, which races with
// the ServeHTTP auth read in SingR's live-refresh deployment.
func TestServiceUsersConcurrent(t *testing.T) {
	s := newUserTestService()
	const n = 200

	uids := make([]int, n)
	pws := make([]string, n)
	for i := 0; i < n; i++ {
		uids[i] = i
		pws[i] = "pw" + strconv.Itoa(i)
	}
	s.UpdateUsers(uids, pws)

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for i := 0; i < n; i++ {
					s.users.lookup("pw" + strconv.Itoa(i))
				}
			}
		}()
	}

	var writers sync.WaitGroup

	// Full rebuilds.
	writers.Add(1)
	go func() {
		defer writers.Done()
		for j := 0; j < 500; j++ {
			s.UpdateUsers(uids, pws)
		}
	}()

	// Incremental add / password rotation.
	writers.Add(1)
	go func() {
		defer writers.Done()
		for j := 0; j < 2000; j++ {
			id := j % n
			s.AddUsers([]int{id}, []string{"pw" + strconv.Itoa(id)})
		}
	}()

	// Incremental remove then re-add.
	writers.Add(1)
	go func() {
		defer writers.Done()
		for j := 0; j < 2000; j++ {
			id := j % n
			s.RemoveUsers([]int{id})
			s.AddUsers([]int{id}, []string{"pw" + strconv.Itoa(id)})
		}
	}()

	writers.Wait()
	close(stop)
	readers.Wait()
}
