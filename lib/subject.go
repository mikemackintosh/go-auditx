package auditx

/*
 * euid                         4 bytes
 * egid                         4 bytes
 * ruid                         4 bytes
 * rgid                         4 bytes
 * pid                          4 bytes
 * sessid                       4 bytes
 * terminal ID
 *   portid             4 bytes
 *   machine id         4 bytes
 */

// Subject contains the event attributes, such as both effective and real users
type Subject struct {
	AuditID   uint64
	Euid      uint64
	Egid      uint64
	Ruid      uint64
	Rgid      uint64
	Pid       uint64
	Sessid    uint64
	Portid    uint64
	Machineid uint64
}
