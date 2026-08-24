package a

// --- Aliases produced by instructions the chase must traverse. ---

var ptrMap = map[string]*Policy{"k": {}}

var arrMap = map[string][2]*Policy{"k": {{}, {}}}

var anyPolicy any = &Policy{}

var ptrB = &Policy{Retries: 2}

type policyPtr *Policy

func LookupMutations() {
	ptrMap["k"].Retries = 1 // want `ptrMap is mutated outside of package initialization`
	p, ok := ptrMap["k"]
	if ok {
		p.Retries = 2 // want `ptrMap is mutated outside of package initialization`
	}
	for _, v := range ptrMap {
		v.Retries = 3 // want `ptrMap is mutated outside of package initialization`
	}
	arrMap["k"][0].Retries = 4 // want `arrMap is mutated outside of package initialization`
}

func PhiMutation(cond bool) {
	p := ptr
	if cond {
		p = ptrB
	}
	p.Retries = 5 // want `ptrB? is mutated outside of package initialization`
}

func PhiEscape(cond bool) {
	p := &counter
	if cond {
		p = &seedCount
	}
	registerInt(p) // want `address of (counter|seedCount) escapes`
}

func AssertMutation() {
	anyPolicy.(*Policy).Retries = 6 // want `anyPolicy is mutated outside of package initialization`
}

func ChangeTypeMutation() {
	pp := policyPtr(ptr)
	(*Policy)(pp).Retries = 7 // want `ptr is mutated outside of package initialization`
}

func ArrayPointerMutation() {
	ap := (*[3]int)(seq)
	ap[0] = 8 // want `seq is mutated outside of package initialization`
}

func FreeVarMutation() {
	p := ptr
	func() {
		p.Retries = 9 // want `ptr is mutated outside of package initialization`
	}()
}

func LocalAliasReads() (int, bool) {
	p, ok := ptrMap["k"] // reading the alias is fine
	q := anyPolicy.(*Policy)
	return p.Retries + q.Retries, ok
}

// --- Channels: sends and close mutate the channel's state. ---

var events = make(chan int, 8)

func init() {
	events <- 0 // init-time send: allowed
}

func sendEvent(ch chan int, n int) { ch <- n }

func ChannelMutations() {
	events <- 1          // want `events is mutated outside of package initialization`
	close(events)        // want `events is mutated \(via close\) outside of package initialization`
	sendEvent(events, 2) // want `events is mutated \(via sendEvent\) outside of package initialization`
	<-events             // receives stay unreported
}
