package bsm

var TokenTypeDictionary = map[byte]string{
	0x00: "AUT_INVALID",
	0x11: "AUT_OTHER_FILE32",
	0x12: "AUT_OHEADER",
	0x13: "AUT_TRAILER",
	0x14: "AUT_HEADER32",
	0x15: "AUT_HEADER32_EX",
	0x21: "AUT_DATA",
	0x22: "AUT_IPC",
	0x23: "AUT_PATH",
	0x24: "AUT_SUBJECT32",
	0x25: "AUT_XATPATH",
	0x26: "AUT_PROCESS32",
	0x27: "AUT_RETURN32",
	0x28: "AUT_TEXT",
	0x29: "AUT_OPAQUE",
	0x2a: "AUT_IN_ADDR",
	0x2b: "AUT_IP",
	0x2c: "AUT_IPORT",
	0x2d: "AUT_ARG32",
	0x2e: "AUT_SOCKET",
	0x2f: "AUT_SEQ",
	0x30: "AUT_ACL",
	0x31: "AUT_ATTR",
	0x32: "AUT_IPC_PERM",
	0x33: "AUT_LABEL",
	0x34: "AUT_GROUPS",
	0x35: "AUT_ACE",
	0x38: "AUT_PRIV",
	0x39: "AUT_UPRIV",
	0x3a: "AUT_LIAISON",
	0x3b: "AUT_NEWGROUPS",
	0x3c: "AUT_EXEC_ARGS",
	0x3d: "AUT_EXEC_ENV",
	0x3e: "AUT_ATTR32",
	0x3f: "AUT_UNAUTH",
	0x40: "AUT_XATOM",
	0x41: "AUT_XOBJ",
	0x42: "AUT_XPROTO",
	0x43: "AUT_XSELECT",
	0x44: "AUT_XCOLORMAP",
	0x45: "AUT_XCURSOR",
	0x46: "AUT_XFONT",
	0x47: "AUT_XGC",
	0x48: "AUT_XPIXMAP",
	0x49: "AUT_XPROPERTY",
	0x4a: "AUT_XWINDOW",
	0x4b: "AUT_XCLIENT",
	0x51: "AUT_CMD",
	0x52: "AUT_EXIT",
	0x60: "AUT_ZONENAME",
	0x70: "AUT_HOST",
	0x71: "AUT_ARG64",
	0x72: "AUT_RETURN64",
	0x73: "AUT_ATTR64",
	0x74: "AUT_HEADER64",
	0x75: "AUT_SUBJECT64",
	0x77: "AUT_PROCESS64",
	0x78: "AUT_OTHER_FILE64",
	0x79: "AUT_HEADER64_EX",
	0x7a: "AUT_SUBJECT32_EX",
	0x7b: "AUT_PROCESS32_EX",
	0x7c: "AUT_SUBJECT64_EX",
	0x7d: "AUT_PROCESS64_EX",
	0x7e: "AUT_IN_ADDR_EX",
	0x7f: "AUT_SOCKET_EX",
}

const (
	AUT_INVALID      = 0x00
	AUT_OTHER_FILE32 = 0x11
	AUT_OHEADER      = 0x12
	AUT_TRAILER      = 0x13
	AUT_HEADER32     = 0x14
	AUT_HEADER32_EX  = 0x15
	AUT_DATA         = 0x21
	AUT_IPC          = 0x22
	AUT_PATH         = 0x23
	AUT_SUBJECT32    = 0x24
	AUT_XATPATH      = 0x25
	AUT_PROCESS32    = 0x26
	AUT_RETURN32     = 0x27
	AUT_TEXT         = 0x28
	AUT_OPAQUE       = 0x29
	AUT_IN_ADDR      = 0x2a
	AUT_IP           = 0x2b
	AUT_IPORT        = 0x2c
	AUT_ARG32        = 0x2d
	AUT_SOCKET       = 0x2e
	AUT_SEQ          = 0x2f
	AUT_ACL          = 0x30
	AUT_ATTR         = 0x31
	AUT_IPC_PERM     = 0x32
	AUT_LABEL        = 0x33
	AUT_GROUPS       = 0x34
	AUT_ACE          = 0x35
	AUT_PRIV         = 0x38
	AUT_UPRIV        = 0x39
	AUT_LIAISON      = 0x3a
	AUT_NEWGROUPS    = 0x3b
	AUT_EXEC_ARGS    = 0x3c
	AUT_EXEC_ENV     = 0x3d
	AUT_ATTR32       = 0x3e
	AUT_UNAUTH       = 0x3f
	AUT_XATOM        = 0x40
	AUT_XOBJ         = 0x41
	AUT_XPROTO       = 0x42
	AUT_XSELECT      = 0x43
	AUT_XCOLORMAP    = 0x44
	AUT_XCURSOR      = 0x45
	AUT_XFONT        = 0x46
	AUT_XGC          = 0x47
	AUT_XPIXMAP      = 0x48
	AUT_XPROPERTY    = 0x49
	AUT_XWINDOW      = 0x4a
	AUT_XCLIENT      = 0x4b
	AUT_CMD          = 0x51
	AUT_EXIT         = 0x52
	AUT_ZONENAME     = 0x60
	AUT_HOST         = 0x70
	AUT_ARG64        = 0x71
	AUT_RETURN64     = 0x72
	AUT_ATTR64       = 0x73
	AUT_HEADER64     = 0x74
	AUT_SUBJECT64    = 0x75
	AUT_PROCESS64    = 0x77
	AUT_OTHER_FILE64 = 0x78
	AUT_HEADER64_EX  = 0x79
	AUT_SUBJECT32_EX = 0x7a
	AUT_PROCESS32_EX = 0x7b
	AUT_SUBJECT64_EX = 0x7c
	AUT_PROCESS64_EX = 0x7d
	AUT_IN_ADDR_EX   = 0x7e
	AUT_SOCKET_EX    = 0x7f
)

const (
	AUDIT_PIPE         = "/dev/auditpipe"
	AUDIT_EVENT_FILE   = "/etc/security/audit_event"
	AUDIT_CLASS_FILE   = "/etc/security/audit_class"
	AUDIT_CONTROL_FILE = "/etc/security/audit_control"
	AUDIT_USER_FILE    = "/etc/security/audit_user"
)
